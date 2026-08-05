package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/clientcli"
	"github.com/nomed/yukh-coordination/internal/clientevent"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func TestFourAgentsCompleteConversationReviewAndHandoff(t *testing.T) {
	fixture := newRuntimeFixture(t)
	instances := map[string]string{
		string(bytes.Repeat([]byte("A"), 43)): "019c6f5b-7c00-7000-8000-000000000501",
		string(bytes.Repeat([]byte("B"), 43)): "019c6f5b-7c00-7000-8000-000000000502",
		string(bytes.Repeat([]byte("C"), 43)): "019c6f5b-7c00-7000-8000-000000000503",
		string(bytes.Repeat([]byte("D"), 43)): "019c6f5b-7c00-7000-8000-000000000504",
	}
	authenticator := participantAuthenticator{instances: instances}
	fixture.config.Authenticator = authenticator
	channel := fixture.channel
	channel.Key.TranscriptEpoch = "1"
	if err := fixture.store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	waitReady(t, runtime)
	t.Cleanup(func() {
		cancel()
		<-result
	})

	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	agents := map[string]clientcli.SignalRunner{}
	for index, name := range []string{"A", "B", "C", "D"} {
		token := string(bytes.Repeat([]byte(name), 43))
		label := strings.ToLower(name)
		client, err := coordclient.New(coordclient.Config{BaseURI: fixture.baseURL, ChannelID: channel.Key.ChannelID, ChannelURI: channel.URI, TranscriptEpoch: 1, PageLimit: 100, MaxRecords: 1000}, fixture.client, requestAuthorizer{token: token}, receiptValidator{validator: validator})
		if err != nil {
			t.Fatal(err)
		}
		builder, err := clientevent.New(clientevent.Config{ChannelURI: channel.URI, SourceURI: "urn:yukh:source:qualification-" + label, Participant: clientevent.Participant{ID: "agent:" + label, Kind: "agent"}, Now: func() time.Time { return time.Date(2026, 8, 5, 18, 0, index, 0, time.UTC) }})
		if err != nil {
			t.Fatal(err)
		}
		agents[name] = clientcli.SignalRunner{Builder: builder, Publisher: client}
	}

	for _, name := range []string{"A", "B", "C", "D"} {
		runSignal(t, agents[name], "session", "join", map[string]any{"capabilities": []string{"publish", "replay"}, "status": "available", "session_label": "qualification-" + name})
	}
	work := "https://github.com/nomed/yukh-coordination/issues/7"
	claim := runSignal(t, agents["A"], "work", "claim", map[string]any{"work_uri": work, "generation": "0", "scope": "implementation", "boundary": "four-agent qualification", "expected_active_claims": []string{}})
	claimEvent, claimID := stringField(t, claim, "event_id"), stringField(t, claim, "claim_id")
	progress := runSignal(t, agents["A"], "work", "progress", map[string]any{"work_uri": work, "correlation_id": claimEvent, "causation_id": claimEvent, "claim_id": claimID, "generation": "0", "parent_claim_event_id": claimEvent, "status": "ready_for_review", "summary": "flow implemented", "completed": []string{"publish"}, "remaining": []string{"review"}, "blocked_by": []string{}})
	progressEvent := stringField(t, progress, "event_id")
	question := runSignal(t, agents["A"], "question", "ask", map[string]any{"work_uri": work, "body": "Is the receipt valid?", "requested_from": []string{"agent:B"}, "response_required": true})
	questionEvent := stringField(t, question, "event_id")
	runSignal(t, agents["B"], "question", "answer", map[string]any{"work_uri": work, "correlation_id": questionEvent, "question_event_id": questionEvent, "body": "Verified", "disposition": "answered"})
	review := runSignal(t, agents["A"], "review", "request", map[string]any{"work_uri": work, "claim_id": claimID, "subject": "four-agent flow", "criteria": []string{"verified receipt"}, "independence_required": true})
	reviewEvent, evidenceDigest := stringField(t, review, "event_id"), stringField(t, review, "evidence_set_digest")
	runSignal(t, agents["C"], "review", "verdict", map[string]any{"work_uri": work, "correlation_id": reviewEvent, "review_event_id": reviewEvent, "evidence_set_digest": evidenceDigest, "outcome": "pass", "summary": "independently verified", "findings": []string{}, "reviewer_independent": true})
	offer := runSignal(t, agents["A"], "handoff", "offer", map[string]any{"work_uri": work, "correlation_id": claimEvent, "causation_id": progressEvent, "claim_id": claimID, "generation": "0", "parent_claim_event_id": progressEvent, "to_participant_instance_id": instances[string(bytes.Repeat([]byte("B"), 43))], "boundary": "continue qualification", "next_action": "accept ownership", "unresolved_risks": []string{}})
	offerEvent := stringField(t, offer, "event_id")
	accept := runSignal(t, agents["B"], "handoff", "accept", map[string]any{"work_uri": work, "correlation_id": claimEvent, "offer_event_id": offerEvent, "source_claim_event_id": claimEvent, "handoff_id": stringField(t, offer, "handoff_id"), "claim_id": claimID, "generation": "0", "boundary_digest": stringField(t, offer, "boundary_digest"), "evidence_set_digest": stringField(t, offer, "evidence_set_digest")})
	acceptEvent := stringField(t, accept, "event_id")
	runSignal(t, agents["B"], "work", "claim", map[string]any{"work_uri": work, "generation": "1", "scope": "implementation", "boundary": "successor", "expected_active_claims": []string{claimID}, "predecessor_handoff_event": acceptEvent})
	runSignal(t, agents["A"], "work", "release", map[string]any{"work_uri": work, "correlation_id": claimEvent, "causation_id": acceptEvent, "claim_id": claimID, "generation": "0", "parent_claim_event_id": acceptEvent, "outcome": "superseded", "reason": "handoff complete"})
	runSignal(t, agents["D"], "session", "leave", map[string]any{"reason": "qualification observed"})

	records, err := fixture.store.Read(context.Background(), channel.Key, 0, 100)
	if err != nil || len(records) != 15 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
}

type participantAuthenticator struct{ instances map[string]string }

func (a participantAuthenticator) Authenticate(_ context.Context, authentication httpapi.SessionAuthentication) (httpapi.Identity, error) {
	instance := a.instances[authentication.Credential()]
	if instance == "" {
		return httpapi.Identity{}, httpapi.ErrUnauthenticated
	}
	return httpapi.Identity{TenantID: "tenant:example", PrincipalID: "principal:" + instance, ParticipantInstanceID: instance, SessionEpoch: 1}, nil
}

type requestAuthorizer struct{ token string }

func (a requestAuthorizer) Authorize(request *http.Request) error {
	request.Header.Set("Authorization", "DPoP "+a.token)
	request.Header.Set("DPoP", "a.b.c")
	return nil
}

type receiptValidator struct{ validator *protocol.Validator }

func (v receiptValidator) Verify(raw []byte) error { return v.validator.ValidateReceipt(raw) }

func runSignal(t *testing.T, runner clientcli.SignalRunner, group, action string, input map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if status := runner.Run(context.Background(), []string{group, action}, bytes.NewReader(raw), &output); status != 0 {
		t.Fatalf("%s %s status=%d output=%s", group, action, status, output.Bytes())
	}
	var document struct {
		Result map[string]any `json:"result"`
	}
	if json.Unmarshal(output.Bytes(), &document) != nil || document.Result == nil {
		t.Fatalf("invalid output: %s", output.Bytes())
	}
	return document.Result
}

func stringField(t *testing.T, value map[string]any, name string) string {
	t.Helper()
	result, ok := value[name].(string)
	if !ok || result == "" {
		t.Fatalf("missing %s in %v", name, value)
	}
	return result
}
