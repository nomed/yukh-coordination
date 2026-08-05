package clientcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/clientevent"
)

type signalPublisher struct {
	event []byte
	err   error
}

func (p *signalPublisher) Publish(_ context.Context, event []byte) (coordclient.PublishResult, error) {
	p.event = append([]byte(nil), event...)
	if p.err != nil {
		return coordclient.PublishResult{}, p.err
	}
	return coordclient.PublishResult{Outcome: "appended", Receipt: json.RawMessage(`{"verified":true}`)}, nil
}

func signalBuilder(t *testing.T) *clientevent.Builder {
	t.Helper()
	builder, err := clientevent.New(clientevent.Config{
		ChannelURI: "https://coord.example/channels/test", SourceURI: "urn:yukh:source:cli-test",
		Participant: clientevent.Participant{ID: "agent:test", Kind: "agent"},
		Now:         func() time.Time { return time.Date(2026, 8, 5, 17, 0, 0, 0, time.UTC) },
		NewID:       func() (string, error) { return "019c6f5b-7c00-7000-8000-000000000401", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func TestSignalRunnerBuildsPublishesAndReturnsVerifiedIdentifiers(t *testing.T) {
	publisher := &signalPublisher{}
	runner := SignalRunner{Builder: signalBuilder(t), Publisher: publisher}
	input := bytes.NewBufferString(`{"capabilities":["publish","replay"],"status":"available","session_label":"worker"}`)
	var stdout bytes.Buffer
	if status := runner.Run(context.Background(), []string{"session", "join"}, input, &stdout); status != 0 {
		t.Fatalf("status=%d output=%s", status, stdout.Bytes())
	}
	var value map[string]any
	if json.Unmarshal(stdout.Bytes(), &value) != nil || value["status"] != "ok" || len(publisher.event) == 0 || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("output=%s event=%s", stdout.Bytes(), publisher.event)
	}
}

func TestSignalRunnerRejectsUnknownFieldsAndMapsConflict(t *testing.T) {
	runner := SignalRunner{Builder: signalBuilder(t), Publisher: &signalPublisher{}}
	var stdout bytes.Buffer
	input := bytes.NewBufferString(`{"capabilities":["publish"],"status":"available","token":"secret"}`)
	if status := runner.Run(context.Background(), []string{"session", "join"}, input, &stdout); status != 2 || bytes.Contains(stdout.Bytes(), []byte("secret")) {
		t.Fatalf("status=%d output=%s", status, stdout.Bytes())
	}
	stdout.Reset()
	runner.Publisher = &signalPublisher{err: errors.New("private: " + coordclient.ErrConflict.Error())}
	input = bytes.NewBufferString(`{"capabilities":["publish"],"status":"available"}`)
	if status := runner.Run(context.Background(), []string{"session", "join"}, input, &stdout); status != 7 {
		t.Fatalf("wrapped non-sentinel status=%d output=%s", status, stdout.Bytes())
	}
	stdout.Reset()
	runner.Publisher = &signalPublisher{err: coordclient.ErrConflict}
	input = bytes.NewBufferString(`{"capabilities":["publish"],"status":"available"}`)
	if status := runner.Run(context.Background(), []string{"session", "join"}, input, &stdout); status != 5 || !bytes.Contains(stdout.Bytes(), []byte("YKC-CONFLICT-001")) {
		t.Fatalf("status=%d output=%s", status, stdout.Bytes())
	}
}
