package primitiveshttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/coordination/memory"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

type fixture struct {
	identity primitivesauth.Identity
	calls    []string
	key      primitives.SealingKey
	opens    int
}

func TestHandlerAdmitsCanonicalBoundedAcquire(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	identity, _ := primitivesauth.NewIdentity("tenant-a", "principal-a")
	key, _ := primitives.NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	fixture := &fixture{identity: identity, key: key}
	sealer, _ := primitives.NewAEADSealer(fixture, bytes.NewReader(bytes.Repeat([]byte{2}, 256)))
	service, _ := primitives.NewService(store, store, sealer, fixture, 1)
	pipeline, _ := primitivesauth.NewPipeline(fixture, fixture, fixture)
	bridge, _ := NewBridge(pipeline, service)
	handler, err := NewHandler(bridge, "https://coordination.invalid", 1, time.Second)
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
	return value.identity, nil
}
func (value *fixture) AuthorizeAction(context.Context, primitivesauth.Identity, primitivesauth.Action) error {
	value.calls = append(value.calls, "action")
	return nil
}
func (value *fixture) AuthorizeScope(context.Context, primitivesauth.Identity, primitivesauth.Action, coordination.Digest) error {
	value.calls = append(value.calls, "scope")
	return nil
}
func (value *fixture) Active(context.Context) (primitives.SealingKey, error) { return value.key, nil }
func (value *fixture) Open(context.Context, string) (primitives.SealingKey, error) {
	value.calls = append(value.calls, "open")
	value.opens++
	return value.key, nil
}
func (*fixture) NewTokenID() ([16]byte, error) { return [16]byte{1}, nil }

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
	service, _ := primitives.NewService(store, store, sealer, fixture, 1)
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
	valid, err := bridge.Inspect(context.Background(), authentication, acquired.Capability)
	if err != nil || !valid {
		t.Fatalf("inspect: %v %v", valid, err)
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
