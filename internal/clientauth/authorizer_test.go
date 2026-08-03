package clientauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const (
	testParticipant  = "01890f3e-7b00-7000-8000-000000000001"
	testKeyReference = "test:key:version:1"
)

type memoryCredentialStore struct {
	mu       sync.Mutex
	record   *SessionRecord
	revision uint64
	err      error
	loads    int
}

func (s *memoryCredentialStore) Load(context.Context, string) (StoredSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.err != nil {
		return StoredSession{}, s.err
	}
	if s.record == nil {
		return StoredSession{}, ErrCredentialMissing
	}
	revision, _ := NewRevision(fmt.Sprintf("revision:%d", s.revision))
	return NewStoredSession(s.record, revision)
}

func (s *memoryCredentialStore) Save(_ context.Context, _ string, expected Revision, record *SessionRecord) (Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return Revision{}, s.err
	}
	if !expected.valid() || s.record == nil && !expected.absent || s.record != nil && expected.value != fmt.Sprintf("revision:%d", s.revision) {
		return Revision{}, ErrCredentialConflict
	}
	copy, err := record.clone()
	if err != nil {
		return Revision{}, ErrCredentialStore
	}
	s.record = copy
	s.revision++
	return NewRevision(fmt.Sprintf("revision:%d", s.revision))
}

func (s *memoryCredentialStore) Delete(_ context.Context, _ string, expected Revision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if s.record == nil || !expected.valid() || expected.absent || expected.value != fmt.Sprintf("revision:%d", s.revision) {
		return ErrCredentialConflict
	}
	s.record = nil
	s.revision++
	return nil
}

type testProofSigner struct {
	reference string
	key       *ecdsa.PrivateKey
	jwk       PublicP256JWK
	publicErr error
	signErr   error
	mutate    func([64]byte) [64]byte
	signs     int
}

func (s *testProofSigner) KeyReference() string { return s.reference }
func (s *testProofSigner) PublicJWK() (PublicP256JWK, error) {
	if s.publicErr != nil {
		return PublicP256JWK{}, s.publicErr
	}
	return s.jwk, nil
}
func (s *testProofSigner) SignES256(_ context.Context, input []byte) ([64]byte, error) {
	s.signs++
	if s.signErr != nil {
		return [64]byte{}, s.signErr
	}
	digest := sha256.Sum256(input)
	r, valueS, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return [64]byte{}, err
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	valueS.FillBytes(signature[32:])
	if s.mutate != nil {
		signature = s.mutate(signature)
	}
	return signature, nil
}

type memorySignerStore struct {
	signer  ProofSigner
	err     error
	opens   int
	retired []string
}

func (s *memorySignerStore) ProvisionP256(context.Context, string) (ProvisionedSigner, error) {
	if s.err != nil {
		return ProvisionedSigner{}, s.err
	}
	return NewProvisionedSigner(s.signer, false)
}
func (s *memorySignerStore) Open(context.Context, string) (ProofSigner, error) {
	s.opens++
	if s.err != nil {
		return nil, s.err
	}
	return s.signer, nil
}
func (s *memorySignerStore) Retire(_ context.Context, reference string) error {
	s.retired = append(s.retired, reference)
	return s.err
}

type testExternalTokenSource struct {
	expected [32]byte
	token    *BoundAccessToken
}

func (s *testExternalTokenSource) Acquire(_ context.Context, key PublicP256JWK) (*BoundAccessToken, error) {
	if key.Thumbprint() != s.expected {
		return nil, ErrExternalToken
	}
	return s.token, nil
}

func TestAuthorizerCreatesServerCompatibleFreshProof(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record, signer := testSession(t, now)
	store := &memoryCredentialStore{record: record, revision: 1}
	signerStore := &memorySignerStore{signer: signer}
	authorizer, err := NewAuthorizer(store, signerStore, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	identifiers := []uuid.UUID{
		uuid.MustParse("01890f3e-7b00-7000-8000-000000000002"),
		uuid.MustParse("01890f3e-7b00-7000-8000-000000000003"),
	}
	authorizer.newJTI = func() (uuid.UUID, error) { value := identifiers[0]; identifiers = identifiers[1:]; return value, nil }

	first := newRequest(t)
	if err := authorizer.Authorize(first); err != nil {
		t.Fatal(err)
	}
	second := newRequest(t)
	if err := authorizer.Authorize(second); err != nil {
		t.Fatal(err)
	}
	if store.loads != 2 || signerStore.opens != 2 || signer.signs != 2 {
		t.Fatalf("request custody counts: load=%d open=%d sign=%d", store.loads, signerStore.opens, signer.signs)
	}
	if first.Header.Get("DPoP") == second.Header.Get("DPoP") {
		t.Fatal("proof was reused")
	}
	if got := first.Header.Get("Authorization"); got != "DPoP "+record.sessionToken {
		t.Fatalf("unexpected authorization %q", got)
	}

	target := "https://relay.example/coordination/v1/channels/release/transcripts/1/records"
	verified, err := identity.NewDPoPVerifier().Verify(first.Header.Get("DPoP"), record.sessionToken, http.MethodGet, target)
	if err != nil {
		t.Fatalf("server rejected proof: %v", err)
	}
	if verified.JTI != "01890f3e-7b00-7000-8000-000000000002" {
		t.Fatalf("unexpected jti %q", verified.JTI)
	}

	object, err := jose.ParseSigned(first.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := signer.jwk.publicKey()
	payload, err := object.Verify(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(record.sessionToken))
	if claims.HTU != target || claims.HTM != http.MethodGet || claims.IAT != now.Unix() || claims.ATH != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestAuthorizerRejectsSignerSubstitutionAndInvalidSignature(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record, signer := testSession(t, now)
	store := &memoryCredentialStore{record: record, revision: 1}

	other := newTestSigner(t, testKeyReference, 2)
	authorizer, err := NewAuthorizer(store, &memorySignerStore{signer: other}, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	request := newRequest(t)
	if err := authorizer.Authorize(request); !errors.Is(err, ErrProofKeyMissing) {
		t.Fatalf("substitution: %v", err)
	}
	if other.signs != 0 || request.Header.Get("DPoP") != "" {
		t.Fatal("substituted key reached signing or request")
	}

	signer.mutate = func([64]byte) [64]byte { return [64]byte{} }
	authorizer, err = NewAuthorizer(store, &memorySignerStore{signer: signer}, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	request = newRequest(t)
	if err := authorizer.Authorize(request); !errors.Is(err, ErrProofSigner) {
		t.Fatalf("invalid signature: %v", err)
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("DPoP") != "" {
		t.Fatal("invalid signature mutated request")
	}
}

func TestCredentialStoreCASRejectsConcurrentReplacementAndStaleDelete(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, _ := testSession(t, now)
	store := &memoryCredentialStore{}
	type outcome struct {
		revision Revision
		err      error
	}
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			revision, err := store.Save(context.Background(), "default", AbsentRevision(), record)
			outcomes <- outcome{revision, err}
		}()
	}
	var firstRevision Revision
	var successes, conflicts int
	for range 2 {
		result := <-outcomes
		switch {
		case result.err == nil:
			successes++
			firstRevision = result.revision
		case errors.Is(result.err, ErrCredentialConflict):
			conflicts++
		default:
			t.Fatalf("unexpected create outcome: %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS outcomes: success=%d conflict=%d", successes, conflicts)
	}
	secondRevision, err := store.Save(context.Background(), "default", firstRevision, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), "default", firstRevision); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := store.Delete(context.Background(), "default", secondRevision); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedPublicKeyFailsBeforeSigning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, signer := testSession(t, now)
	signer.jwk = PublicP256JWK{}
	record.proofJWKThumbprint = signer.jwk.Thumbprint()
	authorizer, err := NewAuthorizer(&memoryCredentialStore{record: record, revision: 1}, &memorySignerStore{signer: signer}, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrProofSigner) {
		t.Fatalf("malformed JWK: %v", err)
	}
	if signer.signs != 0 {
		t.Fatal("malformed public key reached signer")
	}
}

func TestAuthorizerFailsClosedAndSanitizesProviderErrors(t *testing.T) {
	_, signer := testSession(t, time.Now().UTC().Truncate(time.Millisecond))
	if _, err := NewAuthorizer(nil, &memorySignerStore{signer: signer}, "default"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("nil store: %v", err)
	}
	if _, err := NewAuthorizer(&memoryCredentialStore{}, nil, "default"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("nil signer store: %v", err)
	}
	if _, err := NewAuthorizer(&memoryCredentialStore{}, &memorySignerStore{signer: signer}, "../credentials"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("unsafe profile: %v", err)
	}

	providerSecret := errors.New("provider leaked /tmp/plaintext-token")
	authorizer, err := NewAuthorizer(&memoryCredentialStore{err: providerSecret}, &memorySignerStore{signer: signer}, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrCredentialStore) || strings.Contains(err.Error(), providerSecret.Error()) {
		t.Fatalf("store failure: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	record, _ := testSession(t, now)
	authorizer, err = NewAuthorizer(&memoryCredentialStore{record: record, revision: 1}, &memorySignerStore{err: providerSecret}, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrProofSigner) || strings.Contains(err.Error(), providerSecret.Error()) {
		t.Fatalf("signer failure: %v", err)
	}
}

func TestRecordTokenRevisionAndExternalTokenAreRedacted(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, signer := testSession(t, now)
	token := record.sessionToken
	revision, _ := NewRevision("provider:secret:revision")
	stored, err := NewStoredSession(record, revision)
	if err != nil {
		t.Fatal(err)
	}
	external, err := NewBoundAccessToken("header.payload.signature", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	source := &testExternalTokenSource{expected: signer.jwk.Thumbprint(), token: external}
	acquired, err := source.Acquire(context.Background(), signer.jwk)
	if err != nil {
		t.Fatal(err)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v %v %#v", record, record, stored, stored, acquired, acquired)
	if strings.Contains(formatted, token) || strings.Contains(formatted, revision.value) || strings.Contains(formatted, external.credential) || formatted != "SessionRecord{REDACTED} SessionRecord{REDACTED} StoredSession{REDACTED} StoredSession{REDACTED} BoundAccessToken{REDACTED} BoundAccessToken{REDACTED}" {
		t.Fatalf("disclosure: %s", formatted)
	}

	typeOfRecord := reflect.TypeOf(*record)
	for index := 0; index < typeOfRecord.NumField(); index++ {
		if typeOfRecord.Field(index).Type == reflect.TypeOf((*ecdsa.PrivateKey)(nil)) {
			t.Fatal("session record contains private key")
		}
		if typeOfRecord.Field(index).PkgPath == "" {
			t.Fatalf("exported session field %s", typeOfRecord.Field(index).Name)
		}
	}
	if record.SpecVersion() != "0.1" || record.ParticipantInstanceID() != testParticipant || record.SessionEpoch() != 1 || !record.IssuedAt().Equal(now) || !record.ExpiresAt().Equal(now.Add(time.Minute)) {
		t.Fatal("metadata mismatch")
	}
	providerRevision, present := revision.ProviderValue()
	if record.Credential() != token || record.ProofKeyReference() != testKeyReference || record.ProofJWKThumbprint() != signer.jwk.Thumbprint() || providerRevision != revision.value || !present || acquired.Credential() != external.credential {
		t.Fatal("provider-boundary accessor mismatch")
	}
	if value, present := AbsentRevision().ProviderValue(); value != "" || present {
		t.Fatal("absent revision exposed a provider value")
	}
}

func TestSessionRecordRejectsMalformedCustodyData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, signer := testSession(t, now)
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	thumbprint := signer.jwk.Thumbprint()
	cases := []struct {
		name, participant, token, reference string
		epoch                               uint64
		issued, expires                     time.Time
		thumbprint                          [32]byte
	}{
		{"uuid version", "01890f3e-7b00-4000-8000-000000000001", token, testKeyReference, 1, now, now.Add(time.Minute), thumbprint},
		{"epoch zero", testParticipant, token, testKeyReference, 0, now, now.Add(time.Minute), thumbprint},
		{"token", testParticipant, "plaintext", testKeyReference, 1, now, now.Add(time.Minute), thumbprint},
		{"timestamp precision", testParticipant, token, testKeyReference, 1, now.Add(time.Microsecond), now.Add(time.Minute), thumbprint},
		{"lifetime", testParticipant, token, testKeyReference, 1, now, now.Add(16 * time.Minute), thumbprint},
		{"reference", testParticipant, token, "key reference", 1, now, now.Add(time.Minute), thumbprint},
		{"thumbprint", testParticipant, token, testKeyReference, 1, now, now.Add(time.Minute), [32]byte{}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if _, err := NewSessionRecord(item.participant, item.epoch, item.token, item.issued, item.expires, item.reference, item.thumbprint); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAuthorizerRejectsUnsafeRequestAndExpiredSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, signer := testSession(t, now)
	store := &memoryCredentialStore{record: record, revision: 1}
	signerStore := &memorySignerStore{signer: signer}
	authorizer, err := NewAuthorizer(store, signerStore, "default")
	if err != nil {
		t.Fatal(err)
	}
	authorizer.now = func() time.Time { return now }
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
	authorizer.now = record.ExpiresAt
	if err := authorizer.Authorize(newRequest(t)); !errors.Is(err, ErrCredentialMissing) {
		t.Fatalf("expired: %v", err)
	}
}

func TestPublicJWKThumbprintMatchesJOSE(t *testing.T) {
	signer := newTestSigner(t, testKeyReference, 1)
	providerJWK := jose.JSONWebKey{Key: &signer.key.PublicKey}
	want, err := providerJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	got := signer.jwk.Thumbprint()
	if !reflect.DeepEqual(got[:], want) {
		t.Fatalf("thumbprint mismatch: %x != %x", got, want)
	}
}

func testSession(t *testing.T, issuedAt time.Time) (*SessionRecord, *testProofSigner) {
	t.Helper()
	signer := newTestSigner(t, testKeyReference, 1)
	record, err := NewSessionRecord(testParticipant, 1, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), issuedAt, issuedAt.Add(time.Minute), signer.reference, signer.jwk.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	return record, signer
}

func newTestSigner(t *testing.T, reference string, scalar int64) *testProofSigner {
	t.Helper()
	d := big.NewInt(scalar)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	jwk, err := NewPublicP256JWK(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &testProofSigner{reference: reference, key: key, jwk: jwk}
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://relay.example/coordination/v1/channels/release/transcripts/1/records?after=0&limit=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
