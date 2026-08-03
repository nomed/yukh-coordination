package service

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

type TransitionValidator struct{}

func NewTransitionValidator() *TransitionValidator { return &TransitionValidator{} }

type transitionEvent struct {
	id, kind, channel, correlation, causation, work string
	data                                            map[string]any
	evidence                                        []any
}

type claimState struct {
	id, generation, root, work, last string
	active                           bool
	offers                           map[string]*offerState
}

type offerState struct {
	eventID, handoffID, recipient, boundaryDigest, evidenceDigest string
	claim                                                         *claimState
	accepted                                                      bool
}

type transcriptState struct {
	events   map[string]transitionEvent
	claims   map[string]*claimState
	used     map[string]bool
	offers   map[string]*offerState
	accepted map[string]string
}

func (v *TransitionValidator) Validate(view relay.AdmissionView, candidate protocol.Event, participantInstanceID string) error {
	if view == nil || participantInstanceID == "" {
		return relay.ErrInvalidArgument
	}
	state := &transcriptState{events: map[string]transitionEvent{}, claims: map[string]*claimState{}, used: map[string]bool{}, offers: map[string]*offerState{}, accepted: map[string]string{}}
	var after uint64
	for {
		records, err := view.Read(after, 1000)
		if err != nil {
			return err
		}
		for _, record := range records {
			event, err := parseTransitionEvent(record.CanonicalEvent)
			if err != nil {
				return fmt.Errorf("stored transition state: %w", relay.ErrInvalidArgument)
			}
			if err := state.apply(event, receiptParticipant(record), false, false); err != nil {
				return fmt.Errorf("stored transition state: %w", err)
			}
			state.events[event.id] = event
			after = record.Sequence
		}
		if len(records) < 1000 {
			break
		}
	}
	candidateEvent, err := parseTransitionEvent(candidate.Canonical)
	if err != nil {
		return relay.ErrInvalidArgument
	}
	return state.apply(candidateEvent, participantInstanceID, true, true)
}

func (s *transcriptState) apply(event transitionEvent, participant string, enforce, candidate bool) error {
	if event.causation != "" {
		parent, ok := s.events[event.causation]
		if !ok {
			return transitionFailure("UNRESOLVED_CAUSATION", relay.ErrTransitionConflict)
		}
		if parent.channel != event.channel || parent.work != event.work || parent.correlation != event.correlation {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
	}
	data := event.data
	switch event.kind {
	case "claim":
		key := claimKey(text(data, "claim_id"), text(data, "generation"))
		if s.used[key] {
			return transitionFailure("INVALID_CLAIM_TRANSITION", relay.ErrTransitionConflict)
		}
		if predecessor := text(data, "predecessor_handoff_event"); predecessor != "" {
			if s.accepted[predecessor] != participant || event.causation != predecessor {
				return transitionFailure("INVALID_CLAIM_TRANSITION", relay.ErrTransitionConflict)
			}
			delete(s.accepted, predecessor)
		}
		if activeClaims(s.claims, event.work) >= 32 {
			return transitionFailure("RESOURCE_LIMIT", relay.ErrResourceLimit)
		}
		claim := &claimState{id: text(data, "claim_id"), generation: text(data, "generation"), root: event.id, work: event.work, last: event.id, active: true, offers: map[string]*offerState{}}
		s.claims[key], s.used[key] = claim, true
	case "progress", "release", "handoff_offer":
		claim := s.claims[claimKey(text(data, "claim_id"), text(data, "generation"))]
		parent := text(data, "parent_claim_event_id")
		if claim == nil || !claim.active || claim.work != event.work || parent != claim.last || event.causation != parent {
			return transitionFailure("INVALID_CLAIM_TRANSITION", relay.ErrTransitionConflict)
		}
		if event.kind == "release" {
			claim.active, claim.last, claim.offers = false, event.id, map[string]*offerState{}
		} else if event.kind == "progress" {
			claim.last = event.id
		} else {
			if len(claim.offers) >= 32 {
				return transitionFailure("RESOURCE_LIMIT", relay.ErrResourceLimit)
			}
			if enforce {
				if digestBoundary(event) != text(data, "boundary_digest") || digestEvidence(event.evidence) != text(data, "evidence_set_digest") {
					return transitionFailure("INVALID_PAYLOAD", relay.ErrInvalidArgument)
				}
			}
			offer := &offerState{eventID: event.id, handoffID: text(data, "handoff_id"), recipient: text(data, "to_participant_instance_id"), boundaryDigest: text(data, "boundary_digest"), evidenceDigest: text(data, "evidence_set_digest"), claim: claim}
			claim.offers[event.id], s.offers[event.id], claim.last = offer, offer, event.id
		}
	case "handoff_accept":
		offer := s.offers[text(data, "offer_event_id")]
		if offer == nil || offer.accepted || !offer.claim.active || offer.claim.offers[offer.eventID] == nil || event.causation != offer.eventID ||
			participant != offer.recipient || text(data, "handoff_id") != offer.handoffID || text(data, "source_claim_event_id") != offer.claim.root ||
			text(data, "claim_id") != offer.claim.id || text(data, "generation") != offer.claim.generation ||
			text(data, "boundary_digest") != offer.boundaryDigest || text(data, "evidence_set_digest") != offer.evidenceDigest {
			return transitionFailure("HANDOFF_PRECONDITION_FAILED", relay.ErrTransitionConflict)
		}
		offer.accepted, offer.claim.last = true, event.id
		for _, current := range offer.claim.offers {
			current.accepted = true
		}
		offer.claim.offers = map[string]*offerState{}
		s.accepted[event.id] = participant
	case "answer":
		if !referenceType(s, event, text(data, "question_event_id"), "question") {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
	case "verdict":
		if !referenceType(s, event, text(data, "review_event_id"), "review_request") {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
		parent := s.events[text(data, "review_event_id")]
		if text(data, "evidence_set_digest") != text(parent.data, "evidence_set_digest") {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
	case "evidence_verification":
		parentID := text(data, "referenced_event_id")
		parent, ok := s.events[parentID]
		if !ok || event.causation != parentID {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
		matches := 0
		for _, raw := range parent.evidence {
			descriptor := raw.(map[string]any)
			canonical, _ := canonicalJSON(descriptor)
			digest := sha256.Sum256(append([]byte("yukh.evidence-descriptor.v0.1\x00"), canonical...))
			if fmt.Sprintf("sha-256:%x", digest) == text(data, "descriptor_digest") {
				matches++
				digestObject := descriptor["digest"].(map[string]any)
				if text(data, "uri") != text(descriptor, "uri") || text(data, "algorithm") != text(digestObject, "algorithm") || text(data, "expected_digest") != "sha-256:"+text(digestObject, "value") {
					return transitionFailure("INVALID_PAYLOAD", relay.ErrInvalidArgument)
				}
			}
		}
		if matches != 1 {
			return transitionFailure("INVALID_REFERENCE", relay.ErrTransitionConflict)
		}
	}
	if candidate {
		s.events[event.id] = event
	}
	return nil
}

func parseTransitionEvent(raw []byte) (transitionEvent, error) {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return transitionEvent{}, err
	}
	e := transitionEvent{id: text(value, "id"), kind: text(value, "type"), channel: text(value, "channel"), correlation: text(value, "correlation_id"), causation: text(value, "causation_id"), data: value["data"].(map[string]any), evidence: value["evidence"].([]any)}
	if work, ok := value["work"].(map[string]any); ok {
		e.work = text(work, "uri")
	}
	return e, nil
}

func receiptParticipant(record relay.AcceptedRecord) string {
	var value map[string]any
	_ = json.Unmarshal(record.UnsignedReceiptPreimage, &value)
	return text(value, "participant_instance_id")
}

func referenceType(s *transcriptState, event transitionEvent, id, kind string) bool {
	parent, ok := s.events[id]
	return ok && event.causation == id && parent.kind == kind
}
func claimKey(id, generation string) string { return id + "\x00" + generation }
func activeClaims(claims map[string]*claimState, work string) int {
	count := 0
	for _, claim := range claims {
		if claim.active && claim.work == work {
			count++
		}
	}
	return count
}
func text(value map[string]any, key string) string { result, _ := value[key].(string); return result }
func transitionFailure(code string, sentinel error) error {
	return fmt.Errorf("%s: %w", code, sentinel)
}

func digestEvidence(evidence []any) string {
	canonical, _ := canonicalJSON(evidence)
	digest := sha256.Sum256(append([]byte("yukh.evidence-set.v0.1\x00"), canonical...))
	return fmt.Sprintf("sha-256:%x", digest)
}
func digestBoundary(event transitionEvent) string {
	d := event.data
	value := map[string]any{"work_uri": event.work, "claim_id": text(d, "claim_id"), "claim_generation": text(d, "generation"), "boundary": text(d, "boundary"), "next_action": text(d, "next_action"), "unresolved_risks": d["unresolved_risks"]}
	canonical, _ := canonicalJSON(value)
	digest := sha256.Sum256(append([]byte("yukh.handoff-boundary.v0.1\x00"), canonical...))
	return fmt.Sprintf("sha-256:%x", digest)
}
