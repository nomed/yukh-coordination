// Package clientevent constructs closed RFC-0013 coordination events.
package clientevent

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

var ErrInvalid = errors.New("coordination event: invalid input")

type Participant struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Display string `json:"display,omitempty"`
}

type Config struct {
	ChannelURI  string
	SourceURI   string
	Participant Participant
	Now         func() time.Time
	NewID       func() (string, error)
}

type Builder struct {
	config    Config
	validator *protocol.Validator
}

type Result struct {
	Canonical []byte
	EventID   string
	ClaimID   string
}

type Join struct {
	Capabilities []string
	Status       string
	SessionLabel string
}

type Claim struct {
	WorkURI              string
	Generation           string
	Scope                string
	Boundary             string
	GovernanceRef        string
	ExpectedActiveClaims []string
	PredecessorHandoff   string
}

type Progress struct {
	WorkURI            string
	CorrelationID      string
	CausationID        string
	ClaimID            string
	Generation         string
	ParentClaimEventID string
	Status             string
	Summary            string
	Completed          []string
	Remaining          []string
	BlockedBy          []string
}

func New(config Config) (*Builder, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = func() (string, error) {
			value, err := uuid.NewV7()
			return value.String(), err
		}
	}
	if !exactURI(config.ChannelURI) || !exactURI(config.SourceURI) || config.Participant.ID == "" || len(config.Participant.ID) > 256 || !oneOf(config.Participant.Kind, "person", "session", "agent", "service") || len(config.Participant.Display) > 128 {
		return nil, ErrInvalid
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		return nil, ErrInvalid
	}
	return &Builder{config: config, validator: validator}, nil
}

func (b *Builder) Join(input Join) (Result, error) {
	data := map[string]any{"protocol_versions": []string{"0.1"}, "capabilities": nonNil(input.Capabilities), "status": input.Status}
	if input.SessionLabel != "" {
		data["session_label"] = input.SessionLabel
	}
	return b.build("join", "", "", "", data, false)
}

func (b *Builder) Claim(input Claim) (Result, error) {
	claimID, err := b.config.NewID()
	if err != nil {
		return Result{}, ErrInvalid
	}
	data := map[string]any{"claim_id": claimID, "generation": input.Generation, "scope": input.Scope, "boundary": input.Boundary, "expected_active_claims": nonNil(input.ExpectedActiveClaims)}
	if input.GovernanceRef != "" {
		data["governance_ref"] = input.GovernanceRef
	}
	causation := ""
	if input.PredecessorHandoff != "" {
		data["predecessor_handoff_event"] = input.PredecessorHandoff
		causation = input.PredecessorHandoff
	}
	result, err := b.build("claim", input.WorkURI, "", causation, data, true)
	result.ClaimID = claimID
	return result, err
}

func (b *Builder) Progress(input Progress) (Result, error) {
	data := map[string]any{
		"claim_id": input.ClaimID, "generation": input.Generation,
		"parent_claim_event_id": input.ParentClaimEventID, "status": input.Status,
		"summary": input.Summary, "completed": nonNil(input.Completed),
		"remaining": nonNil(input.Remaining), "blocked_by": nonNil(input.BlockedBy),
	}
	return b.build("progress", input.WorkURI, input.CorrelationID, input.CausationID, data, true)
}

func (b *Builder) build(kind, work, correlation, causation string, data map[string]any, hasWork bool) (Result, error) {
	if b == nil || b.validator == nil {
		return Result{}, ErrInvalid
	}
	id, err := b.config.NewID()
	if err != nil {
		return Result{}, ErrInvalid
	}
	if correlation == "" && kind == "claim" {
		correlation = id
	}
	now := b.config.Now().UTC()
	if now.IsZero() {
		return Result{}, ErrInvalid
	}
	event := map[string]any{
		"specversion": "0.1", "id": id, "type": kind,
		"channel": b.config.ChannelURI, "source": b.config.SourceURI,
		"participant": b.config.Participant,
		"time":        now.Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"),
		"data":        data, "evidence": []any{}, "extensions": map[string]string{},
	}
	if hasWork {
		event["work"] = map[string]string{"uri": work}
		event["correlation_id"] = correlation
	}
	if causation != "" {
		event["causation_id"] = causation
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return Result{}, ErrInvalid
	}
	canonical, err := protocol.Canonicalize(raw)
	if err != nil {
		return Result{}, ErrInvalid
	}
	if _, err := b.validator.Validate(canonical); err != nil {
		return Result{}, ErrInvalid
	}
	return Result{Canonical: canonical, EventID: id}, nil
}

func exactURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.User == nil && parsed.Fragment == "" && parsed.String() == value && len(value) <= 2048
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
