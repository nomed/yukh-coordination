package primitivesstaging

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

func TestAuthenticationPersistsReplayAndAdmitsOnlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	registration, token, proofKey := testRegistration(t, now)
	path := filepath.Join(t.TempDir(), "replays.db")
	store, err := OpenReplayStore(path, 128, now)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://coordination.staging.example/v1/nonce/consume"
	proof := testProof(t, proofKey, token, target, now, "proof-jti-00000001")
	material, err := primitivesauth.NewRequestAuthentication(token, proof, "POST", target)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewAuthenticator(registration, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticator.Authenticate(context.Background(), material)
	if err != nil || identity.Tenant() != "tenant-a" || identity.Principal() != "mcp-staging" {
		t.Fatalf("authentication failed: %v", err)
	}
	if _, err := authenticator.Authenticate(context.Background(), material); !errors.Is(err, primitivesauth.ErrUnauthenticated) {
		t.Fatalf("replay error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenReplayStore(path, 128, now)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	authenticator, _ = NewAuthenticator(registration, reopened, func() time.Time { return now })
	if _, err := authenticator.Authenticate(context.Background(), material); !errors.Is(err, primitivesauth.ErrUnauthenticated) {
		t.Fatalf("durable replay error = %v", err)
	}
}

func TestConcurrentProofHasSingleWinner(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	registration, token, proofKey := testRegistration(t, now)
	store, err := OpenReplayStore(filepath.Join(t.TempDir(), "replays.db"), 128, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	target := "https://coordination.staging.example/v1/lease/acquire"
	proof := testProof(t, proofKey, token, target, now, "proof-jti-00000002")
	material, _ := primitivesauth.NewRequestAuthentication(token, proof, "POST", target)
	authenticator, _ := NewAuthenticator(registration, store, func() time.Time { return now })
	var admitted atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := authenticator.Authenticate(context.Background(), material); err == nil {
				admitted.Add(1)
			}
		}()
	}
	group.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("admitted = %d, want 1", admitted.Load())
	}
}

func TestAuthenticationRejectsBindingChangesAndClockRollback(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	registration, token, proofKey := testRegistration(t, now)
	store, err := OpenReplayStore(filepath.Join(t.TempDir(), "replays.db"), 128, now)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	target := "https://coordination.staging.example/v1/lease/inspect"
	proof := testProof(t, proofKey, token, target, now, "proof-jti-00000003")
	changed, _ := primitivesauth.NewRequestAuthentication(token, proof, "POST", target+"/changed")
	authenticator, _ := NewAuthenticator(registration, store, func() time.Time { return now })
	if _, err := authenticator.Authenticate(context.Background(), changed); !errors.Is(err, primitivesauth.ErrUnauthenticated) {
		t.Fatalf("target binding error = %v", err)
	}
	if store.Ready(now.Add(-6 * time.Second)) {
		t.Fatal("store reported ready after clock rollback")
	}
}

func TestClosedConfigAndPathValidation(t *testing.T) {
	dir := t.TempDir()
	paths := []string{"tls.crt", "tls.key", "ca.crt", "registration.json", "registration.sig"}
	for _, name := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	value := configJSON{
		Profile: Profile, PublicBaseURI: "https://coordination.staging.example", PublicBind: "10.0.0.8:8443", OperationsBind: "127.0.0.1:9090",
		TLSCertificatePath: filepath.Join(dir, "tls.crt"), TLSPrivateKeyPath: filepath.Join(dir, "tls.key"), TLSTrustBundlePath: filepath.Join(dir, "ca.crt"),
		RegistrationPath: filepath.Join(dir, "registration.json"), RegistrationSignaturePath: filepath.Join(dir, "registration.sig"), ReplayDatabasePath: filepath.Join(dir, "replays.db"),
		AuditDatabasePath: filepath.Join(dir, "audit.db"),
		RegistrationKeyID: "coordination-staging-1", RegistrationPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RequestDeadlineMS: 1000, MaxConcurrentRequests: 16, MaxReplayEntries: 1024, Epoch: 1,
	}
	raw, _ := json.Marshal(value)
	config, err := ParseConfig(raw)
	if err != nil || config.ValidatePaths() != nil {
		t.Fatalf("valid config rejected: parse=%v validate=%v", err, config.ValidatePaths())
	}
	if _, err := ParseConfig(append(raw[:len(raw)-1], []byte(`,"unexpected":true}`)...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field error = %v", err)
	}
	value.PublicBind = "0.0.0.0:8443"
	raw, _ = json.Marshal(value)
	if _, err := ParseConfig(raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public bind error = %v", err)
	}
	descriptors, err := NewSecretDescriptors(3, 4)
	if err != nil || descriptors.NATSCredential() != 3 || descriptors.CapabilityKey() != 4 {
		t.Fatalf("valid descriptors rejected: %v", err)
	}
	if _, err := json.Marshal(descriptors); !errors.Is(err, ErrInvalid) {
		t.Fatalf("descriptors serialized: %v", err)
	}
	if _, err := NewSecretDescriptors(3, 3); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate descriptor error = %v", err)
	}
}

func testRegistration(t *testing.T, now time.Time) (*Registration, string, *ecdsa.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &proofKey.PublicKey}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	token := "staging-token-fixture-value"
	tokenDigest := sha256.Sum256([]byte("yukh-coordination:staging-token:v1\n" + token))
	value := registrationJSON{
		Actions:        []string{string(primitivesauth.NonceConsume), string(primitivesauth.LeaseAcquire), string(primitivesauth.LeaseInspect), string(primitivesauth.LeaseRenew), string(primitivesauth.LeaseRelease)},
		DPoPThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint), ExpiresAt: now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000Z"), IssuedAt: now.Format("2006-01-02T15:04:05.000Z"),
		KeyID: "coordination-staging-1", PrincipalID: "mcp-staging", Profile: registrationProfile, TenantID: "tenant-a", TokenDigest: base64.RawURLEncoding.EncodeToString(tokenDigest[:]),
	}
	raw, _ := json.Marshal(value)
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, raw)
	registration, err := VerifyRegistration(raw, []byte(base64.RawURLEncoding.EncodeToString(signature)), publicKey, value.KeyID, now)
	if err != nil {
		t.Fatal(err)
	}
	return registration, token, proofKey
}

func testProof(t *testing.T, key *ecdsa.PrivateKey, token, target string, now time.Time, jti string) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &key.PublicKey})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(token))
	payload := fmt.Sprintf(`{"ath":"%s","htm":"POST","htu":"%s","iat":%d,"jti":"%s"}`, base64.RawURLEncoding.EncodeToString(digest[:]), target, now.Unix(), jti)
	object, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
