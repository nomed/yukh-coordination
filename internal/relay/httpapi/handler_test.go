package httpapi_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const routeBase = "https://coord.example/coordination/v1/channels/channel:test/transcripts/1"

func TestAuthenticationAndAdmissionPrecedeApplication(t *testing.T) {
	authenticator := &fakeAuthenticator{err: errors.New("invalid token")}
	authorizer := &fakeAuthorizer{decision: allowedDecision()}
	application := &fakeApplication{}
	handler := newHandler(t, authenticator, authorizer, application)

	request := request(http.MethodGet, routeBase+"/records", "")
	request.Header.Set("Accept", httpapi.TranscriptMediaType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unexpected authentication response: %d %s", response.Code, response.Body.String())
	}
	if authenticator.calls != 1 || authorizer.calls != 0 || application.replayCalls != 0 {
		t.Fatalf("boundary order violated: authn=%d authz=%d app=%d", authenticator.calls, authorizer.calls, application.replayCalls)
	}
}

func TestDeniedResourceUsesNonEnumeratingResponse(t *testing.T) {
	application := &fakeApplication{}
	denied := newHandler(t, &fakeAuthenticator{}, &fakeAuthorizer{}, application)
	request := request(http.MethodGet, routeBase+"/records", "")
	request.Header.Set("Accept", httpapi.TranscriptMediaType)
	response := httptest.NewRecorder()
	denied.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound || problemCode(t, response) != "resource_unavailable" {
		t.Fatalf("unexpected denial: %d %s", response.Code, response.Body.String())
	}
	if application.replayCalls != 0 {
		t.Fatal("denied request reached application")
	}
}

func TestTenantComesOnlyFromAuthenticatedIdentity(t *testing.T) {
	authorizer := &fakeAuthorizer{decision: allowedDecision()}
	application := &fakeApplication{replayPage: []byte(`{"complete":true}`)}
	handler := newHandler(t, &fakeAuthenticator{}, authorizer, application)
	request := request(http.MethodGet, routeBase+"/records?after=4&limit=7", "")
	request.Header.Set("Accept", httpapi.TranscriptMediaType)
	request.Header.Set("X-Tenant-ID", "tenant:attacker")
	request.Header.Set("X-Forwarded-User", "principal:attacker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
	if authorizer.last.Identity.TenantID != "tenant:trusted" || authorizer.last.Channel.TenantID != "tenant:trusted" {
		t.Fatalf("client influenced tenant: %#v", authorizer.last)
	}
	if application.lastReplay.After != 4 || application.lastReplay.Limit != 7 {
		t.Fatalf("cursor not propagated: %#v", application.lastReplay)
	}
}

func TestAppendMediaTypeOutcomesAndPendingSignature(t *testing.T) {
	application := &fakeApplication{appendResponse: httpapi.AppendResponse{
		Outcome: relay.AppendOutcomeAppended, CanonicalReceipt: []byte(`{"signed":true}`),
	}}
	handler := newHandler(t, &fakeAuthenticator{}, &fakeAuthorizer{decision: allowedDecision()}, application)
	appendRequest := request(http.MethodPost, routeBase+"/events", `{"id":"event-1"}`)
	appendRequest.Header.Set("Content-Type", "application/yukh-event+json;version=0.1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, appendRequest)
	if response.Code != http.StatusCreated || response.Header().Get("Content-Type") != httpapi.ReceiptMediaType {
		t.Fatalf("unexpected append: %d %s", response.Code, response.Body.String())
	}

	application.appendResponse.Outcome = relay.AppendOutcomeDuplicate
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, requestClone(appendRequest))
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected duplicate: %d %s", response.Code, response.Body.String())
	}

	application.appendErr = relay.ErrSignaturePending
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request(http.MethodPost, routeBase+"/events", `{"id":"event-1"}`))
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing media type was admitted: %d", response.Code)
	}
	pendingRequest := request(http.MethodPost, routeBase+"/events", `{"id":"event-1"}`)
	pendingRequest.Header.Set("Content-Type", "application/yukh-event+json;version=0.1")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, pendingRequest)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "3" || problemCode(t, response) != "temporarily_unavailable" {
		t.Fatalf("pending signature leaked success: %d %s", response.Code, response.Body.String())
	}
}

func TestCursorAndPathCanonicalizationFailBeforeAuthentication(t *testing.T) {
	for _, target := range []string{
		routeBase + "/records?after=01",
		routeBase + "/records?limit=1001",
		routeBase + "/records?after=9007199254740992",
		routeBase + "/records?unknown=1",
		"https://coord.example/coordination/v1/channels/channel%2Fescape/transcripts/1/records",
	} {
		t.Run(target, func(t *testing.T) {
			authenticator := &fakeAuthenticator{}
			handler := newHandler(t, authenticator, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request(http.MethodGet, target, ""))
			if response.Code != http.StatusBadRequest || authenticator.calls != 0 {
				t.Fatalf("non-canonical target crossed authentication: %d calls=%d", response.Code, authenticator.calls)
			}
		})
	}
}

func TestSSEOrdersRecordsAndStopsAtUnsignedBoundary(t *testing.T) {
	boundary := uint64(7)
	items := make(chan httpapi.StreamItem, 3)
	items <- httpapi.StreamItem{Record: &httpapi.StreamRecord{Sequence: 5, CanonicalRecord: []byte(`{"sequence":"5"}`)}}
	items <- httpapi.StreamItem{Record: &httpapi.StreamRecord{Sequence: 6, CanonicalRecord: []byte(`{"sequence":"6"}`)}}
	items <- httpapi.StreamItem{IncompleteBoundary: &boundary}
	close(items)
	application := &fakeApplication{streamItems: items}
	handler := newHandler(t, &fakeAuthenticator{}, &fakeAuthorizer{decision: allowedDecision()}, application)
	request := request(http.MethodGet, routeBase+"/stream", "")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "4")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	body := response.Body.String()
	for _, expected := range []string{"retry: 3000", "id: 5", "id: 6", "event: boundary-incomplete", `{"sequence":"7"}`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("stream missing %q:\n%s", expected, body)
		}
	}
	if strings.Contains(body, "id: 7") {
		t.Fatalf("unsigned boundary advanced cursor:\n%s", body)
	}
}

func TestSSERevocationTerminatesWithoutDelivery(t *testing.T) {
	revoked := make(chan struct{})
	close(revoked)
	items := make(chan httpapi.StreamItem)
	authorizer := &fakeAuthorizer{decision: allowedDecision()}
	authorizer.decision.Revoked = revoked
	handler := newHandler(t, &fakeAuthenticator{}, authorizer, &fakeApplication{streamItems: items})
	request := request(http.MethodGet, routeBase+"/stream", "")
	request.Header.Set("Accept", "text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if strings.Contains(response.Body.String(), "event: record") {
		t.Fatalf("record delivered after revocation: %s", response.Body.String())
	}
}

func TestTLSAndBearerAreMandatory(t *testing.T) {
	handler := newHandler(t, &fakeAuthenticator{}, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
	request := request(http.MethodGet, routeBase+"/records", "")
	request.TLS = nil
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || problemCode(t, response) != "tls_required" {
		t.Fatalf("plaintext bearer request accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestMalformedBearerNeverReachesAuthenticator(t *testing.T) {
	for _, credential := range []string{"Bearer", "Basic abc", "Bearer abc,def", "Bearer abc=def", "Bearer abc token"} {
		t.Run(credential, func(t *testing.T) {
			authenticator := &fakeAuthenticator{}
			handler := newHandler(t, authenticator, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
			request := request(http.MethodGet, routeBase+"/records", "")
			request.Header.Set("Authorization", credential)
			request.Header.Set("Accept", httpapi.TranscriptMediaType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || authenticator.calls != 0 {
				t.Fatalf("malformed bearer crossed authenticator: %d calls=%d", response.Code, authenticator.calls)
			}
		})
	}
}

type fakeAuthenticator struct {
	calls int
	err   error
}

func (a *fakeAuthenticator) Authenticate(_ context.Context, token string) (httpapi.Identity, error) {
	a.calls++
	if token != "test-token" && a.err == nil {
		return httpapi.Identity{}, errors.New("unexpected token")
	}
	return httpapi.Identity{
		TenantID: "tenant:trusted", PrincipalID: "principal:trusted",
		ParticipantInstanceID: "participant:1", SessionEpoch: 1,
	}, a.err
}

type fakeAuthorizer struct {
	calls    int
	decision httpapi.Decision
	last     httpapi.AccessRequest
}

func (a *fakeAuthorizer) Authorize(_ context.Context, request httpapi.AccessRequest) (httpapi.Decision, error) {
	a.calls++
	a.last = request
	return a.decision, nil
}

type fakeApplication struct {
	appendCalls    int
	replayCalls    int
	streamCalls    int
	appendResponse httpapi.AppendResponse
	appendErr      error
	replayPage     []byte
	streamItems    <-chan httpapi.StreamItem
	lastReplay     httpapi.ReplayRequest
}

func (a *fakeApplication) Append(_ context.Context, _ httpapi.AdmittedRequest, _ []byte) (httpapi.AppendResponse, error) {
	a.appendCalls++
	return a.appendResponse, a.appendErr
}

func (a *fakeApplication) Replay(_ context.Context, request httpapi.ReplayRequest) ([]byte, error) {
	a.replayCalls++
	a.lastReplay = request
	return a.replayPage, nil
}

func (a *fakeApplication) Stream(_ context.Context, request httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	a.streamCalls++
	a.lastReplay = request
	return a.streamItems, nil
}

func newHandler(t *testing.T, authenticator httpapi.Authenticator, authorizer httpapi.Authorizer, application httpapi.Application) *httpapi.Handler {
	t.Helper()
	handler, err := httpapi.New(authenticator, authorizer, application, httpapi.Config{
		HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Second, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func allowedDecision() httpapi.Decision {
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"decision":"allow"}`), ACLPolicyVersion: "acl-v1", ACLPolicyDigest: "sha-256:test", DecisionReceiptID: "decision-1"}
}

func request(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "Bearer test-token")
	return request
}

func requestClone(original *http.Request) *http.Request {
	clone := request(original.Method, original.URL.String(), `{"id":"event-1"}`)
	clone.Header = original.Header.Clone()
	return clone
}

func problemCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Code
}
