package primitiveshttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/coordination/memory"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

type fixture struct {
	identity  primitivesauth.Identity
	calls     []string
	key       primitives.SealingKey
	opens     int
	authErr   error
	actionErr error
	scopeErr  error
	token     byte
}

type gatedReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *gatedReader) Read([]byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	<-reader.release
	return 0, io.EOF
}

func (reader *gatedReader) Close() error {
	reader.once.Do(func() { close(reader.started) })
	return nil
}

func TestHandlerAdmitsCanonicalBoundedAcquire(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	identity, _ := primitivesauth.NewIdentity("tenant-a", "principal-a")
	key, _ := primitives.NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	fixture := &fixture{identity: identity, key: key}
	sealer, _ := primitives.NewAEADSealer(fixture, bytes.NewReader(bytes.Repeat([]byte{2}, 256)))
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	service, _ := primitives.NewService(store, store, budget, sealer, fixture, 1)
	pipeline, _ := primitivesauth.NewPipeline(fixture, fixture, fixture)
	bridge, _ := NewBridge(pipeline, service)
	handler, err := NewHandler(bridge, "https://coordination.invalid", 1, time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"epoch":1,"expires_at":"2026-08-03T12:00:30.000Z","holder_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","scope_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	request := httptest.NewRequest(http.MethodPost, "https://coordination.invalid/coordination-primitives/v1/leases:acquire", strings.NewReader(body))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", MediaType)
	request.Header.Set("Authorization", "DPoP credential")
	request.Header.Set("DPoP", "a.b.c")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"outcome":"acquired"`) {
		t.Fatalf("response: %d %s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "https://coordination.invalid/coordination-primitives/v1/leases:acquire", strings.NewReader(" "+body))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", MediaType)
	request.Header.Set("Authorization", "DPoP credential")
	request.Header.Set("DPoP", "a.b.c")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("non-canonical response: %d", recorder.Code)
	}
}

func (value *fixture) Authenticate(context.Context, primitivesauth.RequestAuthentication) (primitivesauth.Identity, error) {
	value.calls = append(value.calls, "authenticate")
	return value.identity, value.authErr
}
func (value *fixture) AuthorizeAction(context.Context, primitivesauth.Identity, primitivesauth.Action) error {
	value.calls = append(value.calls, "action")
	return value.actionErr
}
func (value *fixture) AuthorizeScope(context.Context, primitivesauth.Identity, primitivesauth.Action, coordination.Digest) error {
	value.calls = append(value.calls, "scope")
	return value.scopeErr
}

func TestHandlerExercisesEveryRouteAndStableLeaseOutcomes(t *testing.T) {
	handler, _, now := newHandlerFixture(t)
	scope := strings.Repeat("a", 64)
	holder := strings.Repeat("b", 64)
	value := strings.Repeat("c", 64)
	expires := now.Add(30 * time.Second).Format("2006-01-02T15:04:05.000Z")

	nonce := perform(t, handler, "/coordination-primitives/v1/nonces:consume", map[string]any{"epoch": 1, "expires_at": expires, "scope_digest": scope, "value_digest": value})
	assertOutcome(t, nonce, http.StatusOK, "consumed")
	replayed := perform(t, handler, "/coordination-primitives/v1/nonces:consume", map[string]any{"epoch": 1, "expires_at": expires, "scope_digest": scope, "value_digest": value})
	assertOutcome(t, replayed, http.StatusOK, "replayed")

	acquired := perform(t, handler, "/coordination-primitives/v1/leases:acquire", map[string]any{"epoch": 1, "expires_at": expires, "holder_digest": holder, "scope_digest": scope})
	assertOutcome(t, acquired, http.StatusOK, "acquired")
	contended := perform(t, handler, "/coordination-primitives/v1/leases:acquire", map[string]any{"epoch": 1, "expires_at": expires, "holder_digest": strings.Repeat("d", 64), "scope_digest": scope})
	assertProblem(t, contended, http.StatusConflict, "conflict")
	var acquiredBody map[string]any
	if err := json.Unmarshal(acquired.Body.Bytes(), &acquiredBody); err != nil {
		t.Fatal(err)
	}
	capability, ok := acquiredBody["lease_capability"].(string)
	if !ok || capability == "" {
		t.Fatal("missing capability")
	}
	inspected := perform(t, handler, "/coordination-primitives/v1/leases:inspect", map[string]any{"lease_capability": capability})
	assertOutcome(t, inspected, http.StatusOK, "valid")
	renewed := perform(t, handler, "/coordination-primitives/v1/leases:renew", map[string]any{"expires_at": now.Add(40 * time.Second).Format("2006-01-02T15:04:05.000Z"), "lease_capability": capability})
	assertOutcome(t, renewed, http.StatusOK, "renewed")
	var renewedBody map[string]any
	if err := json.Unmarshal(renewed.Body.Bytes(), &renewedBody); err != nil {
		t.Fatal(err)
	}
	renewedCapability := renewedBody["lease_capability"].(string)
	stale := perform(t, handler, "/coordination-primitives/v1/leases:inspect", map[string]any{"lease_capability": capability})
	assertOutcome(t, stale, http.StatusOK, "stale")
	released := perform(t, handler, "/coordination-primitives/v1/leases:release", map[string]any{"lease_capability": renewedCapability})
	assertOutcome(t, released, http.StatusOK, "released")
	afterRelease := perform(t, handler, "/coordination-primitives/v1/leases:inspect", map[string]any{"lease_capability": renewedCapability})
	assertOutcome(t, afterRelease, http.StatusOK, "released")
}

func TestHandlerBoundsFramingAndDeniesWithoutSensitiveDiagnostics(t *testing.T) {
	handler, fixture, now := newHandlerFixture(t)
	scope := strings.Repeat("a", 64)
	body := map[string]any{"epoch": 1, "expires_at": now.Add(30 * time.Second).Format("2006-01-02T15:04:05.000Z"), "holder_digest": strings.Repeat("b", 64), "scope_digest": scope}

	oversized := authenticatedRequest("/coordination-primitives/v1/leases:acquire", strings.NewReader(strings.Repeat("x", 4097)))
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	assertProblem(t, oversizedResponse, http.StatusBadRequest, "invalid_request")

	duplicate := authenticatedRequest("/coordination-primitives/v1/leases:acquire", strings.NewReader(`{"epoch":1,"epoch":1}`))
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	assertProblem(t, duplicateResponse, http.StatusBadRequest, "invalid_request")

	fixture.actionErr = primitivesauth.ErrAccessDenied
	denied := perform(t, handler, "/coordination-primitives/v1/leases:acquire", body)
	assertProblem(t, denied, http.StatusForbidden, "access_denied")
	if strings.Contains(denied.Body.String(), scope) {
		t.Fatal("denial exposed scope")
	}
	fixture.actionErr = nil
	fixture.authErr = errors.New("provider body secret")
	unavailable := perform(t, handler, "/coordination-primitives/v1/leases:acquire", body)
	assertProblem(t, unavailable, http.StatusServiceUnavailable, "temporarily_unavailable")
	if strings.Contains(unavailable.Body.String(), "secret") {
		t.Fatal("provider error escaped")
	}
}

func TestHandlerFailsClosedWhenConfiguredConcurrencyIsExhausted(t *testing.T) {
	handler, _, _ := newHandlerFixture(t)
	handler.slots = make(chan struct{}, 1)
	reader := &gatedReader{started: make(chan struct{}), release: make(chan struct{})}
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := authenticatedRequest("/coordination-primitives/v1/leases:inspect", reader)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		firstDone <- response
	}()
	<-reader.started

	second := perform(t, handler, "/coordination-primitives/v1/leases:inspect", map[string]any{"lease_capability": "opaque"})
	assertProblem(t, second, http.StatusServiceUnavailable, "temporarily_unavailable")
	close(reader.release)
	first := <-firstDone
	assertProblem(t, first, http.StatusBadRequest, "invalid_request")
}

func newHandlerFixture(t *testing.T) (*Handler, *fixture, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := memory.New(time.Minute, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := primitivesauth.NewIdentity("tenant-a", "principal-a")
	key, _ := primitives.NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	fixture := &fixture{identity: identity, key: key}
	sealer, _ := primitives.NewAEADSealer(fixture, bytes.NewReader(bytes.Repeat([]byte{2}, 2048)))
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	service, _ := primitives.NewService(store, store, budget, sealer, fixture, 1)
	pipeline, _ := primitivesauth.NewPipeline(fixture, fixture, fixture)
	bridge, _ := NewBridge(pipeline, service)
	handler, err := NewHandler(bridge, "https://coordination.invalid", 1, time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	return handler, fixture, now
}

func perform(t *testing.T, handler *Handler, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(path, bytes.NewReader(raw))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authenticatedRequest(path string, body io.Reader) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://coordination.invalid"+path, body)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Content-Type", MediaType)
	request.Header.Set("Authorization", "DPoP credential")
	request.Header.Set("DPoP", "a.b.c")
	return request
}

func assertOutcome(t *testing.T, response *httptest.ResponseRecorder, status int, outcome string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"outcome":"`+outcome+`"`) {
		t.Fatalf("response: %d %s", response.Code, response.Body.String())
	}
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("problem: %d %s", response.Code, response.Body.String())
	}
}
func (value *fixture) Active(context.Context) (primitives.SealingKey, error) { return value.key, nil }
func (value *fixture) Open(context.Context, string) (primitives.SealingKey, error) {
	value.calls = append(value.calls, "open")
	value.opens++
	return value.key, nil
}
func (value *fixture) NewTokenID() ([16]byte, error) {
	value.token++
	return [16]byte{value.token}, nil
}

func TestBridgeComposesTwoPhaseSingleOpenLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := memory.New(time.Minute, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := primitivesauth.NewIdentity("tenant-a", "principal-a")
	key, _ := primitives.NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	fixture := &fixture{identity: identity, key: key}
	sealer, _ := primitives.NewAEADSealer(fixture, bytes.NewReader(bytes.Repeat([]byte{2}, 256)))
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	service, _ := primitives.NewService(store, store, budget, sealer, fixture, 1)
	pipeline, _ := primitivesauth.NewPipeline(fixture, fixture, fixture)
	bridge, err := NewBridge(pipeline, service)
	if err != nil {
		t.Fatal(err)
	}
	authentication, _ := primitivesauth.NewRequestAuthentication("credential", "a.b.c", "POST", "https://coordination.invalid/coordination-primitives/v1/leases:acquire")
	scope := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	holder := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	acquired, err := bridge.Acquire(context.Background(), authentication, scope, holder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	fixture.calls = nil
	status, err := bridge.Inspect(context.Background(), authentication, acquired.Capability)
	if err != nil || status != coordination.LeaseValid {
		t.Fatalf("inspect: %v %v", status, err)
	}
	expected := []string{"authenticate", "action", "open", "scope"}
	if len(fixture.calls) != len(expected) {
		t.Fatalf("calls: %v", fixture.calls)
	}
	for index := range expected {
		if fixture.calls[index] != expected[index] {
			t.Fatalf("calls: %v", fixture.calls)
		}
	}
	if fixture.opens != 1 {
		t.Fatalf("capability opens: %d", fixture.opens)
	}
}
