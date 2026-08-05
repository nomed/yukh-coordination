package clientevent_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientevent"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

var ids = []string{
	"019c6f5b-7c00-7000-8000-000000000101",
	"019c6f5b-7c00-7000-8000-000000000102",
	"019c6f5b-7c00-7000-8000-000000000103",
	"019c6f5b-7c00-7000-8000-000000000104",
}

func builder(t *testing.T) *clientevent.Builder {
	t.Helper()
	position := 0
	builder, err := clientevent.New(clientevent.Config{
		ChannelURI:  "https://coord.example/channels/project-release",
		SourceURI:   "urn:yukh:source:test-agent",
		Participant: clientevent.Participant{ID: "agent:test", Kind: "agent", Display: "Test agent"},
		Now:         func() time.Time { return time.Date(2026, 8, 5, 15, 0, 0, 123456789, time.UTC) },
		NewID: func() (string, error) {
			value := ids[position]
			position++
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func TestBuildsJoinClaimAndProgressAsCanonicalProtocolEvents(t *testing.T) {
	b := builder(t)
	join, err := b.Join(clientevent.Join{Capabilities: []string{"publish", "replay"}, Status: "available", SessionLabel: "implementation"})
	if err != nil {
		t.Fatal(err)
	}
	claim, err := b.Claim(clientevent.Claim{WorkURI: "https://github.com/nomed/yukh-coordination/issues/6", Generation: "0", Scope: "implementation", Boundary: "client commands", ExpectedActiveClaims: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := b.Progress(clientevent.Progress{
		WorkURI:       "https://github.com/nomed/yukh-coordination/issues/6",
		CorrelationID: claim.EventID, CausationID: claim.EventID,
		ClaimID: claim.ClaimID, Generation: "0", ParentClaimEventID: claim.EventID,
		Status: "in_progress", Summary: "publication complete",
		Completed: []string{"publish"}, Remaining: []string{"commands"}, BlockedBy: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []clientevent.Result{join, claim, progress} {
		if _, err := validator.Validate(result.Canonical); err != nil {
			t.Fatal(err)
		}
		canonical, err := protocol.Canonicalize(result.Canonical)
		if err != nil || !bytes.Equal(canonical, result.Canonical) {
			t.Fatalf("non-canonical event: %v", err)
		}
	}
	var value map[string]any
	if json.Unmarshal(progress.Canonical, &value) != nil || value["correlation_id"] != claim.EventID || value["causation_id"] != claim.EventID || value["time"] != "2026-08-05T15:00:00.123Z" {
		t.Fatalf("progress binding: %s", progress.Canonical)
	}
}

func TestRejectsInvalidConfigurationAndPayloadBeforePublication(t *testing.T) {
	if _, err := clientevent.New(clientevent.Config{ChannelURI: "relative", SourceURI: "urn:test", Participant: clientevent.Participant{ID: "agent", Kind: "agent"}}); !errors.Is(err, clientevent.ErrInvalid) {
		t.Fatalf("invalid config: %v", err)
	}
	b := builder(t)
	if _, err := b.Join(clientevent.Join{Capabilities: []string{"admin"}, Status: "available"}); !errors.Is(err, clientevent.ErrInvalid) {
		t.Fatalf("invalid join: %v", err)
	}
	if _, err := b.Claim(clientevent.Claim{WorkURI: "relative", Generation: "0", Scope: "implementation", Boundary: "x"}); !errors.Is(err, clientevent.ErrInvalid) {
		t.Fatalf("invalid claim: %v", err)
	}
}
