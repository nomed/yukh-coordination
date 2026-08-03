package httpapi_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const routeBase = "https://coord.example/coordination/v1/channels/channel:test/transcripts/1"
const testProof = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl"
const testSessionToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestAuthenticationAndAdmissionPrecedeApplication(t *testing.T) {
	authenticator := &fakeAuthenticator{err: httpapi.ErrUnauthenticated}
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
	authenticator := &fakeAuthenticator{}
	handler := newHandler(t, authenticator, authorizer, application)
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
	if authenticator.last.TargetURI() != "https://public.coord.example/coordination/v1/channels/channel:test/transcripts/1/records" {
		t.Fatalf("provider saw non-public or query-bearing target: %q", authenticator.last.TargetURI())
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

func TestTLSIsMandatory(t *testing.T) {
	handler := newHandler(t, &fakeAuthenticator{}, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
	request := request(http.MethodGet, routeBase+"/records", "")
	request.TLS = nil
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || problemCode(t, response) != "tls_required" {
		t.Fatalf("plaintext authenticated request accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestMalformedDPoPNeverReachesAuthenticator(t *testing.T) {
	for _, credential := range []string{"DPoP", "Basic abc", "Bearer abc", "DPoP abc,def", "DPoP abc token"} {
		t.Run(credential, func(t *testing.T) {
			authenticator := &fakeAuthenticator{}
			handler := newHandler(t, authenticator, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
			request := request(http.MethodGet, routeBase+"/records", "")
			request.Header.Set("Authorization", credential)
			request.Header.Set("Accept", httpapi.TranscriptMediaType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || authenticator.calls != 0 {
				t.Fatalf("malformed DPoP authorization crossed authenticator: %d calls=%d", response.Code, authenticator.calls)
			}
		})
	}
}

func TestMalformedProofNeverReachesAuthenticator(t *testing.T) {
	for _, proof := range []string{"", "a.b", "a.b.c.d", "a..c", "a.b.c=", "a.b.c d", strings.Repeat("a", 16_385)} {
		t.Run(fmt.Sprintf("length-%d", len(proof)), func(t *testing.T) {
			authenticator := &fakeAuthenticator{}
			handler := newHandler(t, authenticator, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
			request := request(http.MethodGet, routeBase+"/records", "")
			request.Header.Set("Accept", httpapi.TranscriptMediaType)
			request.Header.Set("DPoP", proof)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || authenticator.calls != 0 {
				t.Fatalf("malformed proof crossed authenticator: %d calls=%d", response.Code, authenticator.calls)
			}
		})
	}

	authenticator := &fakeAuthenticator{}
	handler := newHandler(t, authenticator, &fakeAuthorizer{decision: allowedDecision()}, &fakeApplication{})
	request := request(http.MethodGet, routeBase+"/records", "")
	request.Header.Add("DPoP", "d.e.f")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || authenticator.calls != 0 {
		t.Fatalf("duplicate proof crossed authenticator: %d calls=%d", response.Code, authenticator.calls)
	}
}

func TestNewRequiresClosedPublicBaseAndBootstrapper(t *testing.T) {
	for name, base := range map[string]string{
		"empty": "", "http": "http://coord.example", "userinfo": "https://user@coord.example",
		"query": "https://coord.example?x=1", "fragment": "https://coord.example/#x", "trailing-slash": "https://coord.example/prefix/",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := httpapi.New(&fakeBootstrapper{}, &fakeAuthenticator{}, &fakeAuthorizer{}, &fakeApplication{}, httpapi.Config{
				PublicBaseURI: base, HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Minute, WriteTimeout: time.Second,
			})
			if !errors.Is(err, relay.ErrInvalidArgument) {
				t.Fatalf("invalid public base accepted: %q: %v", base, err)
			}
		})
	}
	_, err := httpapi.New(nil, &fakeAuthenticator{}, &fakeAuthorizer{}, &fakeApplication{}, httpapi.Config{
		PublicBaseURI: "https://coord.example", HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Minute, WriteTimeout: time.Second,
	})
	if !errors.Is(err, relay.ErrInvalidArgument) {
		t.Fatalf("nil bootstrapper accepted: %v", err)
	}
}

func TestBootstrapProducesClosedCanonicalSession(t *testing.T) {
	issuedAt := time.Date(2026, 8, 3, 5, 15, 0, 0, time.UTC)
	bootstrapper := &fakeBootstrapper{issued: httpapi.IssuedSession{
		SessionToken: testSessionToken, ParticipantInstanceID: "01989f0e-56b7-7e01-915e-a7748f7f6204",
		SessionEpoch: 7, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(15 * time.Minute),
	}}
	handler := newFullHandler(t, bootstrapper, &fakeAuthenticator{}, &fakeAuthorizer{}, &fakeApplication{})
	request := httptest.NewRequest(http.MethodPost, "https://hostile.invalid/coordination/v1/sessions", nil)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "DPoP external-token")
	request.Header.Set("DPoP", testProof)
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	expected := `{"expires_at":"2026-08-03T05:30:00.000Z","participant_instance_id":"01989f0e-56b7-7e01-915e-a7748f7f6204","session_epoch":7,"session_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","specversion":"0.1","token_type":"DPoP"}`
	if response.Code != http.StatusCreated || response.Body.String() != expected || response.Header().Get("Content-Type") != httpapi.SessionMediaType || response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("unexpected bootstrap response: %d %q %#v", response.Code, response.Body.String(), response.Header())
	}
	if bootstrapper.calls != 1 || bootstrapper.last.Credential() != "external-token" || bootstrapper.last.Proof() != testProof || bootstrapper.last.Method() != http.MethodPost || bootstrapper.last.TargetURI() != "https://public.coord.example/coordination/v1/sessions" {
		t.Fatalf("unexpected bootstrap material: calls=%d material=%#v", bootstrapper.calls, bootstrapper.last)
	}
}

func TestBootstrapFramingFailsBeforeProvider(t *testing.T) {
	cases := map[string]func(*http.Request){
		"query":        func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"body":         func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 },
		"content-type": func(r *http.Request) { r.Header.Set("Content-Type", "application/json") },
		"encoding":     func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") },
		"cookie":       func(r *http.Request) { r.Header.Set("Cookie", "session=bad") },
		"chunked":      func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bootstrapper := &fakeBootstrapper{}
			handler := newFullHandler(t, bootstrapper, &fakeAuthenticator{}, &fakeAuthorizer{}, &fakeApplication{})
			request := httptest.NewRequest(http.MethodPost, "https://coord.example/coordination/v1/sessions", nil)
			request.TLS = &tls.ConnectionState{}
			request.Header.Set("Authorization", "DPoP external-token")
			request.Header.Set("DPoP", testProof)
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || bootstrapper.calls != 0 {
				t.Fatalf("framing crossed provider: status=%d calls=%d", response.Code, bootstrapper.calls)
			}
		})
	}
}

func TestAuthenticationMaterialIsSeparatedAndRedacted(t *testing.T) {
	bootstrapper := &fakeBootstrapper{err: httpapi.ErrUnauthenticated}
	authenticator := &fakeAuthenticator{err: httpapi.ErrUnauthenticated}
	handler := newFullHandler(t, bootstrapper, authenticator, &fakeAuthorizer{}, &fakeApplication{})

	bootstrap := httptest.NewRequest(http.MethodPost, "https://coord.example/coordination/v1/sessions", nil)
	bootstrap.TLS = &tls.ConnectionState{}
	bootstrap.Header.Set("Authorization", "DPoP external-secret")
	bootstrap.Header.Set("DPoP", testProof)
	bootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(bootstrapResponse, bootstrap)
	if bootstrapResponse.Code != http.StatusUnauthorized || bootstrapper.calls != 1 || authenticator.calls != 0 || bootstrapResponse.Header().Get("WWW-Authenticate") != `DPoP algs="ES256"` {
		t.Fatalf("bootstrap trust boundary failed: %d %d %d", bootstrapResponse.Code, bootstrapper.calls, authenticator.calls)
	}

	resource := request(http.MethodGet, routeBase+"/records", "")
	resource.Header.Set("Accept", httpapi.TranscriptMediaType)
	resourceResponse := httptest.NewRecorder()
	handler.ServeHTTP(resourceResponse, resource)
	if resourceResponse.Code != http.StatusUnauthorized || bootstrapper.calls != 1 || authenticator.calls != 1 {
		t.Fatalf("resource trust boundary failed: %d %d %d", resourceResponse.Code, bootstrapper.calls, authenticator.calls)
	}
	for _, formatted := range []string{fmt.Sprint(bootstrapper.last), fmt.Sprintf("%#v", bootstrapper.last), fmt.Sprint(authenticator.last), fmt.Sprintf("%#v", authenticator.last)} {
		if strings.Contains(formatted, "secret") || strings.Contains(formatted, testProof) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("authentication material leaked through formatting: %q", formatted)
		}
	}
}

func TestMalformedProviderSuccessAndUnknownErrorAreUnavailable(t *testing.T) {
	for name, bootstrapper := range map[string]*fakeBootstrapper{
		"malformed-success": {},
		"unknown-error":     {err: errors.New("provider secret detail")},
	} {
		t.Run(name, func(t *testing.T) {
			handler := newFullHandler(t, bootstrapper, &fakeAuthenticator{}, &fakeAuthorizer{}, &fakeApplication{})
			request := httptest.NewRequest(http.MethodPost, "https://coord.example/coordination/v1/sessions", nil)
			request.TLS = &tls.ConnectionState{}
			request.Header.Set("Authorization", "DPoP external-token")
			request.Header.Set("DPoP", testProof)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || problemCode(t, response) != "temporarily_unavailable" || strings.Contains(response.Body.String(), "secret") || response.Header().Get("Retry-After") != "3" {
				t.Fatalf("provider failure leaked: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

type fakeAuthenticator struct {
	calls int
	err   error
	last  httpapi.SessionAuthentication
}

func (a *fakeAuthenticator) Authenticate(_ context.Context, authentication httpapi.SessionAuthentication) (httpapi.Identity, error) {
	a.calls++
	a.last = authentication
	if authentication.Credential() != testSessionToken && a.err == nil {
		return httpapi.Identity{}, errors.New("unexpected token")
	}
	return httpapi.Identity{
		TenantID: "tenant:trusted", PrincipalID: "principal:trusted",
		ParticipantInstanceID: "01989f0e-56b7-7e01-915e-a7748f7f6204", SessionEpoch: 1,
	}, a.err
}

type fakeBootstrapper struct {
	calls  int
	err    error
	issued httpapi.IssuedSession
	last   httpapi.BootstrapAuthentication
}

func (b *fakeBootstrapper) Bootstrap(_ context.Context, authentication httpapi.BootstrapAuthentication) (httpapi.IssuedSession, error) {
	b.calls++
	b.last = authentication
	return b.issued, b.err
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
	return newFullHandler(t, &fakeBootstrapper{}, authenticator, authorizer, application)
}

func newFullHandler(t *testing.T, bootstrapper httpapi.SessionBootstrapper, authenticator httpapi.Authenticator, authorizer httpapi.Authorizer, application httpapi.Application) *httpapi.Handler {
	t.Helper()
	handler, err := httpapi.New(bootstrapper, authenticator, authorizer, application, httpapi.Config{
		PublicBaseURI: "https://public.coord.example", HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Second, WriteTimeout: time.Second,
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
	request.Header.Set("Authorization", "DPoP "+testSessionToken)
	request.Header.Set("DPoP", testProof)
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
