package clientcli

import (
	"context"
	"io"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/clientevent"
)

const maxSignalInput = 65_536

type SignalBuilder interface {
	BuildJSON(string, []byte) (clientevent.Result, error)
}

type Publisher interface {
	Publish(context.Context, []byte) (coordclient.PublishResult, error)
}

type SignalRunner struct {
	Builder   SignalBuilder
	Publisher Publisher
}

type signalResult struct {
	EventID           string                    `json:"event_id"`
	ClaimID           string                    `json:"claim_id,omitempty"`
	HandoffID         string                    `json:"handoff_id,omitempty"`
	BoundaryDigest    string                    `json:"boundary_digest,omitempty"`
	EvidenceSetDigest string                    `json:"evidence_set_digest,omitempty"`
	Publication       coordclient.PublishResult `json:"publication"`
}

func (r SignalRunner) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	command := "unknown"
	if len(args) == 2 {
		command = args[0] + " " + args[1]
	}
	if len(args) != 2 || !signalCommand(command) || r.Builder == nil || r.Publisher == nil || stdin == nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxSignalInput+1))
	if err != nil || len(raw) == 0 || len(raw) > maxSignalInput {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	event, err := r.Builder.BuildJSON(command, raw)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	published, err := r.Publisher.Publish(ctx, event.Canonical)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: code(err)}, exit(err))
	}
	result := signalResult{EventID: event.EventID, ClaimID: event.ClaimID, HandoffID: event.HandoffID, BoundaryDigest: event.BoundaryDigest, EvidenceSetDigest: event.EvidenceSetDigest, Publication: published}
	return write(stdout, output{Schema: 1, Status: "ok", Command: command, Result: result}, 0)
}

func signalCommand(command string) bool {
	switch command {
	case "session join", "session leave", "work claim", "work progress", "work release",
		"question ask", "question answer", "review request", "review verdict",
		"handoff offer", "handoff accept":
		return true
	default:
		return false
	}
}
