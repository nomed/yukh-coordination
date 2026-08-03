package service

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/memory"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func TestApplicationAppendRetryReplayAndLiveHandoff(t *testing.T) {
	application, validator, admitted, event := newApplicationFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := application.Stream(ctx, httpapi.ReplayRequest{AdmittedRequest: admitted, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}

	first, err := application.Append(context.Background(), admitted, event)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != relay.AppendOutcomeAppended || validator.ValidateReceipt(first.CanonicalReceipt) != nil {
		t.Fatalf("invalid append response: %#v", first)
	}
	duplicate, err := application.Append(context.Background(), admitted, event)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Outcome != relay.AppendOutcomeDuplicate || !bytes.Equal(first.CanonicalReceipt, duplicate.CanonicalReceipt) {
		t.Fatal("exact retry did not return the original canonical receipt")
	}

	select {
	case item := <-stream:
		if item.IncompleteBoundary != nil {
			// The durable unsigned preimage may be observed while the external
			// signer is attaching the signature. RFC-0005 requires a boundary and
			// reconnect, never delivery across it.
			stream, err = application.Stream(ctx, httpapi.ReplayRequest{AdmittedRequest: admitted, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			item = <-stream
		}
		if item.Err != nil || item.Record == nil || item.Record.Sequence != 1 || !json.Valid(item.Record.CanonicalRecord) {
			t.Fatalf("invalid live record after reconnect: %#v", item)
		}
	case <-time.After(time.Second):
		t.Fatal("append between subscribe and durable read was lost")
	}

	page, err := application.Replay(context.Background(), httpapi.ReplayRequest{AdmittedRequest: admitted, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(page, &document); err != nil {
		t.Fatal(err)
	}
	if document["completeness"] != "complete" || document["high_water_sequence"] != float64(1) || len(document["records"].([]any)) != 1 {
		t.Fatalf("unexpected replay page: %s", page)
	}
}

func TestApplicationRejectsWrongChannelBeforeAppend(t *testing.T) {
	application, _, admitted, event := newApplicationFixture(t)
	changed := bytes.Replace(event, []byte("https://coord.example/channels/project-release"), []byte("https://coord.example/channels/another"), 1)
	canonical, err := jsoncanonicalizer.Transform(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Append(context.Background(), admitted, canonical); err == nil {
		t.Fatal("wrong-channel event was accepted")
	}
	page, err := application.Replay(context.Background(), httpapi.ReplayRequest{AdmittedRequest: admitted, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte(`"event"`)) {
		t.Fatalf("rejected event reached replay: %s", page)
	}
}

func TestLiveChangesCoalescesWithoutBlockingPublisher(t *testing.T) {
	live := NewLiveChanges()
	key := relay.ChannelKey{TenantID: "tenant", ChannelID: "channel", TranscriptEpoch: "0"}
	updates, unsubscribe, err := live.Subscribe(context.Background(), key, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unsubscribe()
	for range 1000 {
		live.Notify(key)
	}
	if len(updates) != 1 {
		t.Fatalf("notification queue length = %d, want 1", len(updates))
	}
}

func newApplicationFixture(t *testing.T) (*RelayApplication, *protocol.Validator, httpapi.AdmittedRequest, []byte) {
	t.Helper()
	root := repositoryRoot(t)
	metadata, err := os.ReadFile(filepath.Join(root, "conformance/canonical/channel.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	validatedMetadata, err := validator.ValidateChannelMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	channel := relay.Channel{
		Key: relay.ChannelKey{TenantID: "tenant:example", ChannelID: "channel:release", TranscriptEpoch: "0"},
		URI: validatedMetadata.ChannelURI, CanonicalMetadata: metadata,
		MetadataDigest: validatedMetadata.Digest, Lifecycle: "active",
	}
	store := memory.New()
	if err := store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	appendService, err := NewAppendService(store, applicationSigner{})
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewRelayApplication(store, appendService, validator, NewLiveChanges())
	if err != nil {
		t.Fatal(err)
	}
	application.clock = func() time.Time { return time.Date(2026, 8, 3, 4, 0, 0, 0, time.UTC) }
	application.newReceiptID = func() (string, error) { return "01989f0e-56b7-7e01-915e-a7748f7f621f", nil }
	eventSource, err := os.ReadFile(filepath.Join(root, "conformance/fixtures/positive/event-join.json"))
	if err != nil {
		t.Fatal(err)
	}
	event, err := protocol.Canonicalize(eventSource)
	if err != nil {
		t.Fatal(err)
	}
	admitted := httpapi.AdmittedRequest{
		Identity: httpapi.Identity{TenantID: "tenant:example", PrincipalID: "principal:fixture", ParticipantInstanceID: "01989f0e-56b7-7e01-915e-a7748f7f6220", SessionEpoch: 1},
		Channel:  channel.Key, AuthorizationBinding: []byte(`{"decision":"allow"}`),
		ACLPolicyVersion: "acl-v1", ACLPolicyDigest: "sha-256:1111111111111111111111111111111111111111111111111111111111111111",
		ACLDecisionReceiptID: "decision-1",
	}
	return application, validator, admitted, event
}

type applicationSigner struct{}

func (applicationSigner) Select(context.Context) (SigningSelection, error) {
	return SigningSelection{KeyID: "key-1", Algorithm: "ed25519"}, nil
}

func (applicationSigner) Sign(context.Context, relay.AcceptedRecord) ([]byte, error) {
	return bytes.Repeat([]byte{0}, 64), nil
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}
