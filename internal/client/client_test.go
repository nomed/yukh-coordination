package client_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const (
	channelID   = "channel:test"
	channelURI  = "https://coord.example/channels/test"
	participant = "019c6f5b-7c00-7000-8000-000000000001"
)

type bootstrapper struct{}

func (bootstrapper) Bootstrap(context.Context, httpapi.BootstrapAuthentication) (httpapi.IssuedSession, error) {
	return httpapi.IssuedSession{}, errors.New("disabled")
}

type authenticator struct{}

func (authenticator) Authenticate(context.Context, httpapi.SessionAuthentication) (httpapi.Identity, error) {
	return httpapi.Identity{TenantID: "tenant:test", PrincipalID: "principal:test", ParticipantInstanceID: participant, SessionEpoch: 1}, nil
}

type authorizer struct{}

func (authorizer) Authorize(context.Context, httpapi.AccessRequest) (httpapi.Decision, error) {
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"allowed":true}`), ACLPolicyVersion: "1", ACLPolicyDigest: "sha-256:" + fmt.Sprintf("%064d", 0), DecisionReceiptID: "decision:test", Revoked: make(chan struct{})}, nil
}

type application struct{ pages map[uint64][]byte }

func (a application) Append(context.Context, httpapi.AdmittedRequest, []byte) (httpapi.AppendResponse, error) {
	return httpapi.AppendResponse{}, errors.New("disabled")
}
func (a application) Replay(_ context.Context, r httpapi.ReplayRequest) ([]byte, error) {
	return a.pages[r.After], nil
}
func (application) Stream(context.Context, httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	return nil, errors.New("disabled")
}

type auth struct{}

func (auth) Authorize(r *http.Request) error {
	r.Header.Set("Authorization", "DPoP AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	r.Header.Set("DPoP", "a.b.c")
	return nil
}

type verifier struct{ calls *int }

func (v verifier) Verify(raw []byte) error {
	var value struct {
		Signature string `json:"signature"`
	}
	if json.Unmarshal(raw, &value) != nil || value.Signature != "valid" {
		return errors.New("invalid")
	}
	*v.calls++
	return nil
}

func canonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func event(t *testing.T, id, kind, work string, data map[string]any) []byte {
	return canonical(t, map[string]any{"specversion": "0.1", "id": id, "type": kind, "source": "https://agent.example/session", "time": "2026-08-03T00:00:00.000Z", "channel": channelURI, "work": map[string]any{"uri": work}, "participant": map[string]any{"id": "agent:test", "instance_id": participant, "session_epoch": "1"}, "correlation_id": id, "data": data, "evidence": []any{}})
}
func record(t *testing.T, sequence uint64, event []byte) map[string]any {
	var eventValue any
	if json.Unmarshal(event, &eventValue) != nil {
		t.Fatal("event")
	}
	digest := sha256.Sum256(event)
	receipt := map[string]any{"specversion": "0.1", "event_id": eventValue.(map[string]any)["id"], "event_digest": fmt.Sprintf("sha-256:%x", digest), "channel_id": channelID, "channel_uri": channelURI, "cursor": strconv.FormatUint(sequence, 10), "sequence": sequence, "transcript_epoch": uint64(1), "participant_instance_id": participant, "signature": "valid"}
	return map[string]any{"event": eventValue, "receipt": receipt}
}
func page(t *testing.T, after uint64, records []map[string]any, completeness string, boundary *uint64) []byte {
	value := map[string]any{"specversion": "0.1", "channel_id": channelID, "channel_uri": channelURI, "transcript_epoch": uint64(1), "after": after, "high_water_sequence": after + uint64(len(records)), "completeness": completeness, "records": records}
	if boundary != nil {
		value["boundary_sequence"] = *boundary
	}
	return canonical(t, value)
}

func testClient(t *testing.T, pages map[uint64][]byte, limit int) (*coordclient.Client, *int) {
	t.Helper()
	handler, err := httpapi.New(bootstrapper{}, authenticator{}, authorizer{}, application{pages: pages}, httpapi.Config{PublicBaseURI: "https://coord.example", HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Minute, WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	calls := 0
	client, err := coordclient.New(coordclient.Config{BaseURI: server.URL, ChannelID: channelID, ChannelURI: channelURI, TranscriptEpoch: 1, PageLimit: limit, MaxRecords: 100}, server.Client(), auth{}, verifier{calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	return client, &calls
}

func TestReplayPagesThroughRealHandlerAndInspectsConflicts(t *testing.T) {
	work := "https://github.com/nomed/yukh-projects/pull/74"
	claim1 := event(t, "019c6f5b-7c00-7000-8000-000000000011", "claim", work, map[string]any{"claim_id": "019c6f5b-7c00-7000-8000-000000000021", "generation": "0", "scope": "implementation", "boundary": "first", "expected_active_claims": []any{}})
	claim2 := event(t, "019c6f5b-7c00-7000-8000-000000000012", "claim", work, map[string]any{"claim_id": "019c6f5b-7c00-7000-8000-000000000022", "generation": "0", "scope": "review", "boundary": "second", "expected_active_claims": []any{}})
	client, calls := testClient(t, map[uint64][]byte{0: page(t, 0, []map[string]any{record(t, 1, claim1)}, "complete", nil), 1: page(t, 1, []map[string]any{record(t, 2, claim2)}, "complete", nil), 2: page(t, 2, []map[string]any{}, "complete", nil)}, 1)
	replay, err := client.Replay(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if replay.HighWaterSequence != 2 || len(replay.Records) != 2 || *calls != 2 {
		t.Fatalf("replay %#v calls=%d", replay, *calls)
	}
	view, err := coordclient.Inspect(replay, work)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != "conflicting" || len(view.Claims) != 2 || len(view.HandoffOfferIDs) != 0 {
		t.Fatalf("view %#v", view)
	}
}

func TestReplayFailsClosedAtBoundaryAndBadReceipt(t *testing.T) {
	work := "https://example.test/work"
	raw := event(t, "019c6f5b-7c00-7000-8000-000000000013", "claim", work, map[string]any{"claim_id": "019c6f5b-7c00-7000-8000-000000000023", "generation": "0"})
	boundary := uint64(2)
	client, _ := testClient(t, map[uint64][]byte{0: page(t, 0, []map[string]any{record(t, 1, raw)}, "incomplete", &boundary)}, 100)
	result, err := client.Replay(context.Background())
	if !errors.Is(err, coordclient.ErrIncomplete) || result.HighWaterSequence != 1 || result.BoundarySequence == nil {
		t.Fatalf("boundary %#v %v", result, err)
	}
	bad := record(t, 1, raw)
	bad["receipt"].(map[string]any)["signature"] = "changed"
	client, _ = testClient(t, map[uint64][]byte{0: page(t, 0, []map[string]any{bad}, "complete", nil)}, 100)
	if _, err = client.Replay(context.Background()); !errors.Is(err, coordclient.ErrInvalidRecord) {
		t.Fatalf("bad receipt %v", err)
	}
}

func TestConfigRejectsInsecureOrAmbientInputs(t *testing.T) {
	for _, base := range []string{"http://coord.example", "https://user@coord.example", "https://coord.example/?x=1"} {
		if _, err := coordclient.New(coordclient.Config{BaseURI: base, ChannelID: channelID, ChannelURI: channelURI, TranscriptEpoch: 1, PageLimit: 100, MaxRecords: 100}, http.DefaultClient, auth{}, verifier{calls: new(int)}); !errors.Is(err, coordclient.ErrInvalidInput) {
			t.Fatalf("accepted %s", base)
		}
	}
}

type targetChangingAuth struct{}
func (targetChangingAuth) Authorize(request *http.Request) error { request.URL.RawQuery = "token=secret"; return nil }

func TestAuthorizerCannotChangeRequestTarget(t *testing.T) {
	client, err := coordclient.New(coordclient.Config{BaseURI:"https://coord.example",ChannelID:channelID,ChannelURI:channelURI,TranscriptEpoch:1,PageLimit:100,MaxRecords:100},http.DefaultClient,targetChangingAuth{},verifier{calls:new(int)})
	if err != nil { t.Fatal(err) }
	if _, err = client.Replay(context.Background()); !errors.Is(err,coordclient.ErrAuthentication) { t.Fatalf("target mutation: %v",err) }
}
