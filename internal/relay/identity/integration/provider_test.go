package integration_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
	identitysqlite "github.com/nomed/yukh-coordination/internal/relay/identity/sqlite"
)

const (
	integrationIssuer   = "https://issuer.example"
	integrationAudience = "https://public.coord.example"
	bootstrapTarget     = integrationAudience + "/coordination/v1/sessions"
	resourceTarget      = integrationAudience + "/coordination/v1/channels/channel:test/transcripts/1/records"
)

func TestRealProviderThroughHTTPEdgeAndReplayBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaPublicJWK(&issuerKey.PublicKey)}})
	}))
	defer jwks.Close()
	roots := x509.NewCertPool()
	roots.AddCert(jwks.Certificate())
	auditor := &recordingAuditor{}
	verifier, err := identity.NewVerifier(context.Background(), identity.VerifierConfig{
		Issuer: integrationIssuer, Audience: integrationAudience,
		JWKS: identity.JWKSConfig{URL: jwks.URL, Roots: roots, Algorithms: []jose.SignatureAlgorithm{jose.RS256}, SoftRefresh: time.Minute, HardMaxAge: 5 * time.Minute, RequestTimeout: time.Second, AuthorityReference: "issuer:integration:key-set", Auditor: auditor},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	registry, err := identitysqlite.Open(filepath.Join(t.TempDir(), "identity.db"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	provider, err := identity.NewProvider(verifier, registry, auditor)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &captureAuthorizer{}
	handler, err := httpapi.New(provider, provider, authorizer, integrationApplication{}, httpapi.Config{
		PublicBaseURI: integrationAudience, HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Second, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	thumbprint := ecThumbprint(t, clientKey)
	external := signRS256(t, issuerKey, map[string]any{"alg": "RS256", "kid": "issuer-key-1", "typ": "at+JWT"}, map[string]any{
		"aud": integrationAudience, "client_id": "client-1", "cnf": map[string]any{"jkt": thumbprint},
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(), "iss": integrationIssuer,
		"jti": "external-token-1", "sub": "subject-1", "tenant_id": "tenant:example",
	})
	bootstrapProof := dpopProof(t, clientKey, external, http.MethodPost, bootstrapTarget, now, "bootstrapProofAB")
	bootstrapRequest := httptest.NewRequest(http.MethodPost, bootstrapTarget, nil)
	bootstrapRequest.TLS = &tls.ConnectionState{}
	bootstrapRequest.Header.Set("Authorization", "DPoP "+external)
	bootstrapRequest.Header.Set("DPoP", bootstrapProof)
	bootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(bootstrapResponse, bootstrapRequest)
	if bootstrapResponse.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrapResponse.Code, bootstrapResponse.Body.String())
	}
	var issued struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(bootstrapResponse.Body.Bytes(), &issued); err != nil || len(issued.SessionToken) != 43 {
		t.Fatalf("session response: %#v, %v", issued, err)
	}

	resourceProof := dpopProof(t, clientKey, issued.SessionToken, http.MethodGet, resourceTarget, time.Now().UTC(), "resourceProofABC")
	requestResource := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, resourceTarget, nil)
		request.TLS = &tls.ConnectionState{}
		request.Header.Set("Authorization", "DPoP "+issued.SessionToken)
		request.Header.Set("DPoP", resourceProof)
		request.Header.Set("Accept", httpapi.TranscriptMediaType)
		return request
	}
	resourceResponse := httptest.NewRecorder()
	handler.ServeHTTP(resourceResponse, requestResource())
	if resourceResponse.Code != http.StatusOK || authorizer.last.TenantID != "tenant:example" || authorizer.last.SessionEpoch != 1 {
		t.Fatalf("resource admission: status=%d identity=%#v", resourceResponse.Code, authorizer.last)
	}
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, requestResource())
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("replayed proof status=%d body=%s", replayResponse.Code, replayResponse.Body.String())
	}
	if got := auditor.snapshot(); len(got) != 4 || got[0].Operation != identity.AuditJWKSRefresh || got[1].Outcome != identity.AuditAllow || got[2].Outcome != identity.AuditAllow || got[3].Reason != identity.AuditReasonProofReplay {
		t.Fatalf("audit sequence: %#v", got)
	}
}

type recordingAuditor struct {
	mu      sync.Mutex
	records []identity.AuditRecord
}

func (a *recordingAuditor) Record(_ context.Context, record identity.AuditRecord) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, record)
	return "audit:receipt:" + big.NewInt(int64(len(a.records))).String(), nil
}

func (*recordingAuditor) Ready(context.Context) error { return nil }

func (a *recordingAuditor) snapshot() []identity.AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]identity.AuditRecord(nil), a.records...)
}

type captureAuthorizer struct{ last httpapi.Identity }

func (a *captureAuthorizer) Authorize(_ context.Context, request httpapi.AccessRequest) (httpapi.Decision, error) {
	a.last = request.Identity
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"allowed":true}`), ACLPolicyVersion: "acl-v1", ACLPolicyDigest: "sha-256:test", DecisionReceiptID: "audit:acl:1"}, nil
}

type integrationApplication struct{}

func (integrationApplication) Append(context.Context, httpapi.AdmittedRequest, []byte) (httpapi.AppendResponse, error) {
	return httpapi.AppendResponse{}, nil
}
func (integrationApplication) Replay(context.Context, httpapi.ReplayRequest) ([]byte, error) {
	return []byte(`{"complete":true}`), nil
}
func (integrationApplication) Stream(context.Context, httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	result := make(chan httpapi.StreamItem)
	close(result)
	return result, nil
}

func rsaPublicJWK(key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"alg": "RS256", "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()), "kid": "issuer-key-1",
		"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "use": "sig",
	}
}

func publicECJWK(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"crv": "P-256", "kty": "EC",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

func ecThumbprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	canonical, err := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{"P-256", "EC", base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func dpopProof(t *testing.T, key *ecdsa.PrivateKey, credential, method, target string, issuedAt time.Time, jti string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(credential))
	return signES256(t, key, map[string]any{"alg": "ES256", "jwk": publicECJWK(key), "typ": "dpop+jwt"}, map[string]any{
		"ath": base64.RawURLEncoding.EncodeToString(digest[:]), "htm": method, "htu": target, "iat": issuedAt.Unix(), "jti": jti,
	})
}

func signRS256(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	input := encodedInput(t, header, claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	input := encodedInput(t, header, claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func encodedInput(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(encodedClaims)
}
