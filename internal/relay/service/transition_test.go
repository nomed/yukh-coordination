package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func TestTransitionValidatorRequiresResolvedCausationAndCurrentClaimParent(t *testing.T) {
	validator := NewTransitionValidator()
	view := &transitionView{}
	claim := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000001", "claim", "", "01989f0e-56b7-7000-8000-000000000001", map[string]any{
		"claim_id": "01989f0e-56b7-7000-8000-000000000101", "generation": "1", "scope": "implementation", "boundary": "scope", "expected_active_claims": []any{},
	}))
	if err := validator.Validate(view, claim, participantID); err != nil {
		t.Fatal(err)
	}
	view.add(claim, participantID)

	progress := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000002", "progress", claim.ID, claim.ID, map[string]any{
		"claim_id": "01989f0e-56b7-7000-8000-000000000101", "generation": "1", "parent_claim_event_id": claim.ID,
	}))
	if err := validator.Validate(view, progress, participantID); err != nil {
		t.Fatal(err)
	}
	view.add(progress, participantID)

	staleRelease := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000003", "release", claim.ID, claim.ID, map[string]any{
		"claim_id": "01989f0e-56b7-7000-8000-000000000101", "generation": "1", "parent_claim_event_id": claim.ID,
	}))
	if err := validator.Validate(view, staleRelease, participantID); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("stale lifecycle parent: %v", err)
	}

	missing := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000004", "answer", "01989f0e-56b7-7000-8000-000000000099", "01989f0e-56b7-7000-8000-000000000050", map[string]any{"question_event_id": "01989f0e-56b7-7000-8000-000000000099"}))
	if err := validator.Validate(view, missing, participantID); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("unresolved causation: %v", err)
	}
}

func TestTransitionValidatorEnforcesClaimLimit(t *testing.T) {
	view := &transitionView{}
	for index := 1; index <= 32; index++ {
		id := fmt.Sprintf("01989f0e-56b7-7%03x-8000-%012x", index, index)
		claimID := fmt.Sprintf("01989f0e-56b7-7%03x-9000-%012x", index, index)
		view.add(transitionCandidate(t, eventDocument(id, "claim", "", id, map[string]any{"claim_id": claimID, "generation": "1"})), participantID)
	}
	id := "01989f0e-56b7-7fff-8000-000000000099"
	candidate := transitionCandidate(t, eventDocument(id, "claim", "", id, map[string]any{"claim_id": "01989f0e-56b7-7fff-9000-000000000099", "generation": "1"}))
	if err := NewTransitionValidator().Validate(view, candidate, participantID); !errors.Is(err, relay.ErrResourceLimit) {
		t.Fatalf("33rd active claim: %v", err)
	}
}

func TestTransitionValidatorHandoffCASBindsRecipientAndSingleAcceptance(t *testing.T) {
	validator := NewTransitionValidator()
	view := &transitionView{}
	claimID := "01989f0e-56b7-7000-9000-000000000101"
	claim := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000011", "claim", "", "01989f0e-56b7-7000-8000-000000000011", map[string]any{"claim_id": claimID, "generation": "1"}))
	view.add(claim, participantID)
	offerMap := eventDocument("01989f0e-56b7-7000-8000-000000000012", "handoff_offer", claim.ID, claim.ID, map[string]any{
		"handoff_id": "01989f0e-56b7-7000-9000-000000000102", "claim_id": claimID, "generation": "1", "parent_claim_event_id": claim.ID,
		"to_participant_instance_id": recipientID, "boundary": "continue", "next_action": "test", "unresolved_risks": []any{},
	})
	offerEvent, _ := parseTransitionEvent(mustCanonical(t, offerMap))
	offerMap["data"].(map[string]any)["boundary_digest"] = digestBoundary(offerEvent)
	offerMap["data"].(map[string]any)["evidence_set_digest"] = digestEvidence([]any{})
	offer := transitionCandidate(t, offerMap)
	if err := validator.Validate(view, offer, participantID); err != nil {
		t.Fatal(err)
	}
	view.add(offer, participantID)
	data := offerMap["data"].(map[string]any)
	acceptData := map[string]any{"handoff_id": data["handoff_id"], "offer_event_id": offer.ID, "source_claim_event_id": claim.ID, "claim_id": claimID, "generation": "1", "boundary_digest": data["boundary_digest"], "evidence_set_digest": data["evidence_set_digest"]}
	accept := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000013", "handoff_accept", offer.ID, claim.ID, acceptData))
	if err := validator.Validate(view, accept, participantID); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("wrong recipient: %v", err)
	}
	if err := validator.Validate(view, accept, recipientID); err != nil {
		t.Fatal(err)
	}
	view.add(accept, recipientID)
	second := transitionCandidate(t, eventDocument("01989f0e-56b7-7000-8000-000000000014", "handoff_accept", offer.ID, claim.ID, acceptData))
	if err := validator.Validate(view, second, recipientID); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("second acceptance: %v", err)
	}
	successorID := "01989f0e-56b7-7000-8000-000000000015"
	successor := transitionCandidate(t, eventDocument(successorID, "claim", accept.ID, successorID, map[string]any{"claim_id": "01989f0e-56b7-7000-9000-000000000103", "generation": "2", "predecessor_handoff_event": accept.ID}))
	if err := validator.Validate(view, successor, participantID); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("wrong successor: %v", err)
	}
	if err := validator.Validate(view, successor, recipientID); err != nil {
		t.Fatalf("accepted successor: %v", err)
	}
}

const participantID = "01989f0e-56b7-7000-8000-000000000201"
const recipientID = "01989f0e-56b7-7000-8000-000000000202"
const workURI = "https://example.test/work/1"
const channelURI = "https://coord.example/channels/test"

func eventDocument(id, kind, causation, correlation string, data map[string]any) map[string]any {
	value := map[string]any{"specversion": "0.1", "id": id, "type": kind, "channel": channelURI, "correlation_id": correlation, "source": "urn:test", "participant": map[string]any{"id": "session:test", "kind": "session"}, "time": "2026-08-03T00:00:00.000Z", "work": map[string]any{"uri": workURI}, "data": data, "evidence": []any{}, "extensions": map[string]any{}}
	if causation != "" {
		value["causation_id"] = causation
	}
	return value
}

func transitionCandidate(t *testing.T, value map[string]any) protocol.Event {
	t.Helper()
	raw := mustCanonical(t, value)
	return protocol.Event{ID: text(value, "id"), Canonical: raw}
}
func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type transitionView struct{ records []relay.AcceptedRecord }

func (v *transitionView) Lookup(id string) (relay.AcceptedRecord, error) {
	for _, r := range v.records {
		if r.EventID == id {
			return r, nil
		}
	}
	return relay.AcceptedRecord{}, relay.ErrEventNotFound
}
func (v *transitionView) Read(after uint64, limit int) ([]relay.AcceptedRecord, error) {
	start := int(after)
	if start >= len(v.records) {
		return nil, nil
	}
	end := min(start+limit, len(v.records))
	return v.records[start:end], nil
}
func (v *transitionView) add(event protocol.Event, participant string) {
	preimage, _ := json.Marshal(map[string]any{"participant_instance_id": participant})
	v.records = append(v.records, relay.AcceptedRecord{Sequence: uint64(len(v.records) + 1), EventID: event.ID, CanonicalEvent: event.Canonical, UnsignedReceiptPreimage: preimage})
}
