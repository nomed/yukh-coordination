package clientauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const testParticipant = "01890f3e-7b00-7000-8000-000000000001"

type memoryStore struct {
	value *SessionCredentials
	err   error
	loads int
}

func (s *memoryStore) Load(context.Context, string) (*SessionCredentials, error) {
	s.loads++
	if s.err != nil {
		return nil, s.err
	}
	return s.value.clone()
}
func (s *memoryStore) Save(_ context.Context, _ string, value *SessionCredentials) error {
	var err error
	s.value, err = value.clone()
	return err
}
func (s *memoryStore) Delete(context.Context, string) error { s.value = nil; return nil }

func TestAuthorizerCreatesServerCompatibleFreshProof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	credentials := testCredentials(t, now.Add(time.Minute))
	store := &memoryStore{value: credentials}
	authorizer, err := NewAuthorizer(store, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	firstJTI := uuid.MustParse("01890f3e-7b00-7000-8000-000000000002")
	secondJTI := uuid.MustParse("01890f3e-7b00-7000-8000-000000000003")
	identifiers := []uuid.UUID{firstJTI, secondJTI}
	authorizer.newJTI = func() (uuid.UUID, error) { value := identifiers[0]; identifiers = identifiers[1:]; return value, nil }

	first := newRequest(t)
	if err := authorizer.Authorize(first); err != nil {
		t.Fatal(err)
	}
	second := newRequest(t)
	if err := authorizer.Authorize(second); err != nil {
		t.Fatal(err)
	}
	if store.loads != 2 {
		t.Fatalf("credentials loaded %d times, want once per request", store.loads)
	}
	if first.Header.Get("DPoP") == second.Header.Get("DPoP") {
		t.Fatal("proof was reused")
	}
	if got := first.Header.Get("Authorization"); got != "DPoP "+credentials.sessionToken {
		t.Fatalf("unexpected authorization %q", got)
	}

	target := "https://relay.example/coordination/v1/channels/release/transcripts/1/records"
	verified, err := identity.NewDPoPVerifier().Verify(first.Header.Get("DPoP"), credentials.sessionToken, http.MethodGet, target)
	if err != nil {
		t.Fatalf("server rejected client proof: %v", err)
	}
	if verified.JTI != firstJTI.String() {
		t.Fatalf("unexpected jti %q", verified.JTI)
	}

	object, err := jose.ParseSigned(first.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if len(object.Signatures) != 1 || object.Signatures[0].Header.ExtraHeaders[jose.HeaderKey("typ")] != "dpop+jwt" || object.Signatures[0].Header.Algorithm != string(jose.ES256) || object.Signatures[0].Header.JSONWebKey == nil || !object.Signatures[0].Header.JSONWebKey.IsPublic() {
		t.Fatal("invalid protected DPoP header")
	}
	payload, err := object.Verify(&credentials.privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(credentials.sessionToken))
	if claims.HTU != target || claims.HTM != http.MethodGet || claims.IAT != now.Unix() || claims.JTI != firstJTI.String() || claims.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestAuthorizerFailsClosedWithoutUsableCredentialStore(t *testing.T) {
	if _, err := NewAuthorizer(nil, "default"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("nil store: %v", err)
	}
	if _, err := NewAuthorizer(&memoryStore{}, "../credentials"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("unsafe profile: %v", err)
	}

	providerSecret := errors.New("provider leaked /tmp/plaintext-token")
	authorizer, err := NewAuthorizer(&memoryStore{err: providerSecret}, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrCredentialStore) || strings.Contains(err.Error(), providerSecret.Error()) {
		t.Fatalf("unsanitized store failure: %v", err)
	}

	expired := testCredentials(t, time.Now().UTC().Truncate(time.Millisecond))
	authorizer, err = NewAuthorizer(&memoryStore{value: expired}, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = expired.ExpiresAt
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expired credential: %v", err)
	}
}

func TestAuthorizerRejectsAmbiguousOrUnsafeRequest(t *testing.T) {
	credentials := testCredentials(t, time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond))
	authorizer, err := NewAuthorizer(&memoryStore{value: credentials}, "default")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*http.Request){
		"http":             func(r *http.Request) { r.URL.Scheme = "http" },
		"lowercase method": func(r *http.Request) { r.Method = "get" },
		"authorization":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer attacker") },
		"proof":            func(r *http.Request) { r.Header.Set("DPoP", "attacker") },
		"cookie":           func(r *http.Request) { r.Header.Set("Cookie", "session=attacker") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := newRequest(t)
			mutate(request)
			if err := authorizer.Authorize(request); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCredentialValidationIsolationAndRedaction(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Millisecond)
	credentials, err := NewSessionCredentials(testParticipant, 1, token, expires, key)
	if err != nil {
		t.Fatal(err)
	}
	key.D.SetInt64(1)
	if !validCredentials(credentials) {
		t.Fatal("caller mutation changed credential key")
	}
	formatted := fmt.Sprintf("%v %#v", credentials, credentials)
	if strings.Contains(formatted, token) || strings.Contains(formatted, credentials.privateKey.D.String()) || formatted != "SessionCredentials{REDACTED} SessionCredentials{REDACTED}" {
		t.Fatalf("credential disclosure: %s", formatted)
	}
	if credentials.SpecVersion() != "0.1" || credentials.ParticipantInstanceID() != testParticipant || credentials.SessionEpoch() != 1 || !credentials.ExpiresAt().Equal(expires) {
		t.Fatal("metadata accessor mismatch")
	}

	invalid := []struct {
		name, participant, token string
		epoch                    uint64
		expires                  time.Time
	}{
		{"uuid version", "01890f3e-7b00-4000-8000-000000000001", token, 1, expires},
		{"epoch zero", testParticipant, token, 0, expires},
		{"token", testParticipant, "plaintext", 1, expires},
		{"timestamp precision", testParticipant, token, 1, expires.Add(time.Microsecond)},
	}
	for _, item := range invalid {
		t.Run(item.name, func(t *testing.T) {
			if _, err := NewSessionCredentials(item.participant, item.epoch, item.token, item.expires, credentials.privateKey); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func testCredentials(t *testing.T, expires time.Time) *SessionCredentials {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewSessionCredentials(testParticipant, 1, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), expires, key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://relay.example/coordination/v1/channels/release/transcripts/1/records?after=0&limit=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
