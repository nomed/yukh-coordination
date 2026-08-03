package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "https://coord.example"
	testTarget   = "https://coord.example/coordination/v1/sessions"
)

type verifierFixture struct {
	t             *testing.T
	now           time.Time
	rsaKey        *rsa.PrivateKey
	dpopKey       *ecdsa.PrivateKey
	server        *httptest.Server
	mu            sync.Mutex
	keys          []testJWK
	status        int
	contentType   string
	redirect      string
	requests      int
	verifier      *Verifier
	accessHeader  map[string]any
	accessClaims  map[string]any
	dpopHeader    map[string]any
	dpopClaims    map[string]any
	externalToken string
}

type testJWK struct {
	Key       *rsa.PublicKey
	KeyID     string
	Algorithm string
	Use       string
}

func newVerifierFixture(t *testing.T) *verifierFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &verifierFixture{
		t: t, now: time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC), rsaKey: rsaKey, dpopKey: dpopKey,
		keys:   []testJWK{{Key: &rsaKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "RS256", Use: "sig"}},
		status: http.StatusOK, contentType: "application/jwk-set+json",
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serveJWKS))
	t.Cleanup(fixture.server.Close)
	thumbprint := fixture.dpopThumbprint(dpopKey)
	fixture.accessHeader = map[string]any{"alg": "RS256", "kid": "issuer-key-1", "typ": "at+JWT"}
	fixture.accessClaims = map[string]any{
		"aud": testAudience, "client_id": "client-1", "cnf": map[string]any{"jkt": thumbprint},
		"exp": fixture.now.Add(10 * time.Minute).Unix(), "iat": fixture.now.Add(-time.Minute).Unix(),
		"iss": testIssuer, "jti": "external-token-1", "sub": "subject-1", "tenant_id": "tenant:example",
	}
	fixture.externalToken = signRS256(t, rsaKey, fixture.accessHeader, fixture.accessClaims)
	fixture.dpopHeader = map[string]any{"alg": "ES256", "jwk": publicECJWK(dpopKey), "typ": "dpop+jwt"}
	fixture.dpopClaims = map[string]any{
		"ath": tokenHash(fixture.externalToken), "htm": "POST", "htu": testTarget,
		"iat": fixture.now.Unix(), "jti": "abcdefghijklmnop",
	}
	fixture.verifier = fixture.newVerifier()
	t.Cleanup(fixture.verifier.Close)
	return fixture
}

func (f *verifierFixture) newVerifier() *Verifier {
	f.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	verifier, err := newVerifier(context.Background(), VerifierConfig{
		Issuer: testIssuer, Audience: testAudience,
		JWKS: JWKSConfig{
			URL: f.server.URL, Roots: pool, Algorithms: []jose.SignatureAlgorithm{jose.RS256},
			SoftRefresh: time.Minute, HardMaxAge: 5 * time.Minute, RequestTimeout: 2 * time.Second,
		},
	}, func() time.Time { return f.now })
	if err != nil {
		f.t.Fatal(err)
	}
	return verifier
}

func (f *verifierFixture) serveJWKS(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.redirect != "" {
		http.Redirect(w, r, f.redirect, http.StatusFound)
		return
	}
	if f.status != http.StatusOK {
		w.WriteHeader(f.status)
		return
	}
	w.Header().Set("Content-Type", f.contentType)
	encoded := make([]map[string]any, 0, len(f.keys))
	for _, key := range f.keys {
		encoded = append(encoded, rsaJWK(key))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": encoded})
}

func TestVerifyBootstrapWithIndependentSignatures(t *testing.T) {
	fixture := newVerifierFixture(t)
	proof := signES256(t, fixture.dpopKey, fixture.dpopHeader, fixture.dpopClaims)
	identity, err := fixture.verifier.VerifyBootstrap(context.Background(), fixture.externalToken, proof, "POST", testTarget)
	if err != nil {
		t.Fatal(err)
	}
	if identity.TenantID != "tenant:example" || identity.PrincipalID != "vqCO_9rM1tW0gw88TdEZG4PbXcBheseFlN3vYgfh4O0" || identity.ProofJTI != "abcdefghijklmnop" || !identity.TokenExpiresAt.Equal(fixture.now.Add(10*time.Minute)) {
		t.Fatalf("unexpected identity: %#v", identity)
	}
	if base64.RawURLEncoding.EncodeToString(identity.DPoPThumbprint[:]) != fixture.dpopThumbprint(fixture.dpopKey) {
		t.Fatal("DPoP thumbprint changed")
	}
}

func TestVerifierReadinessExpiresWithJWKS(t *testing.T) {
	fixture := newVerifierFixture(t)
	if !fixture.verifier.Ready() {
		t.Fatal("fresh JWKS reported unready")
	}
	fixture.now = fixture.now.Add(5 * time.Minute)
	if fixture.verifier.Ready() {
		t.Fatal("hard-stale JWKS reported ready")
	}
}

func TestDPoPProfileRejectsMismatchesAndExtensions(t *testing.T) {
	fixture := newVerifierFixture(t)
	tests := map[string]func(map[string]any, map[string]any){
		"wrong-typ":        func(h, _ map[string]any) { h["typ"] = "JWT" },
		"wrong-alg":        func(h, _ map[string]any) { h["alg"] = "ES384" },
		"header-extension": func(h, _ map[string]any) { h["kid"] = "client-key" },
		"private-jwk": func(h, _ map[string]any) {
			h["jwk"].(map[string]any)["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"wrong-method": func(_, c map[string]any) { c["htm"] = "GET" },
		"wrong-uri":    func(_, c map[string]any) { c["htu"] = testTarget + "/other" },
		"query-uri":    func(_, c map[string]any) { c["htu"] = testTarget + "?x=1" },
		"wrong-ath":    func(_, c map[string]any) { c["ath"] = strings.Repeat("A", 43) },
		"short-jti":    func(_, c map[string]any) { c["jti"] = "short" },
		"future":       func(_, c map[string]any) { c["iat"] = fixture.now.Add(6 * time.Second).Unix() },
		"old":          func(_, c map[string]any) { c["iat"] = fixture.now.Add(-61 * time.Second).Unix() },
		"claim-extra":  func(_, c map[string]any) { c["nonce"] = "unexpected" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			header := cloneMap(fixture.dpopHeader)
			claims := cloneMap(fixture.dpopClaims)
			mutate(header, claims)
			proof := signES256(t, fixture.dpopKey, header, claims)
			if _, err := fixture.verifier.VerifySessionProof(proof, fixture.externalToken, "POST", testTarget); !errors.Is(err, errInvalid) {
				t.Fatalf("invalid proof accepted: %v", err)
			}
		})
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof := signES256(t, otherKey, fixture.dpopHeader, fixture.dpopClaims)
	if _, err := fixture.verifier.VerifySessionProof(proof, fixture.externalToken, "POST", testTarget); !errors.Is(err, errInvalid) {
		t.Fatalf("wrong signature key accepted: %v", err)
	}
}

func TestJWTProfileRejectsAmbiguityAndWrongTrust(t *testing.T) {
	fixture := newVerifierFixture(t)
	tests := map[string]func(map[string]any, map[string]any){
		"missing-typ":    func(h, _ map[string]any) { delete(h, "typ") },
		"id-token-typ":   func(h, _ map[string]any) { h["typ"] = "JWT" },
		"none":           func(h, _ map[string]any) { h["alg"] = "none" },
		"hmac":           func(h, _ map[string]any) { h["alg"] = "HS256" },
		"header-extra":   func(h, _ map[string]any) { h["jku"] = "https://attacker.invalid/keys" },
		"wrong-issuer":   func(_, c map[string]any) { c["iss"] = "https://attacker.invalid" },
		"wrong-audience": func(_, c map[string]any) { c["aud"] = "https://other.example" },
		"multi-audience": func(_, c map[string]any) { c["aud"] = []string{testAudience, "https://other.example"} },
		"wrong-key-binding": func(_, c map[string]any) {
			c["cnf"] = map[string]any{"jkt": strings.Repeat("A", 43)}
		},
		"bad-tenant":    func(_, c map[string]any) { c["tenant_id"] = "Tenant With Spaces" },
		"unknown-claim": func(_, c map[string]any) { c["scope"] = "coordination" },
		"future":        func(_, c map[string]any) { c["iat"] = fixture.now.Add(31 * time.Second).Unix() },
		"old":           func(_, c map[string]any) { c["iat"] = fixture.now.Add(-5*time.Minute - time.Second).Unix() },
		"long-lifetime": func(_, c map[string]any) { c["exp"] = fixture.now.Add(16 * time.Minute).Unix() },
		"expired":       func(_, c map[string]any) { c["exp"] = fixture.now.Add(-time.Second).Unix() },
		"numeric-float": func(_, c map[string]any) { c["iat"] = float64(fixture.now.Unix()) + 0.5 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			header := cloneMap(fixture.accessHeader)
			claims := cloneMap(fixture.accessClaims)
			mutate(header, claims)
			token := signRS256(t, fixture.rsaKey, header, claims)
			dpopClaims := cloneMap(fixture.dpopClaims)
			dpopClaims["ath"] = tokenHash(token)
			proof := signES256(t, fixture.dpopKey, fixture.dpopHeader, dpopClaims)
			if _, err := fixture.verifier.VerifyBootstrap(context.Background(), token, proof, "POST", testTarget); !errors.Is(err, errInvalid) {
				t.Fatalf("invalid token accepted: %v", err)
			}
		})
	}

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongSignature := signRS256(t, otherKey, fixture.accessHeader, fixture.accessClaims)
	claims := cloneMap(fixture.dpopClaims)
	claims["ath"] = tokenHash(wrongSignature)
	proof := signES256(t, fixture.dpopKey, fixture.dpopHeader, claims)
	if _, err := fixture.verifier.VerifyBootstrap(context.Background(), wrongSignature, proof, "POST", testTarget); !errors.Is(err, errInvalid) {
		t.Fatalf("JWT signed by an untrusted key accepted: %v", err)
	}

	for name, token := range map[string]string{
		"jwe":             "a.b.c.d.e",
		"json-serialized": `{"payload":"e30","signatures":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.verifier.verifyExternalToken(context.Background(), token); !errors.Is(err, errInvalid) {
				t.Fatalf("non-compact JWT accepted: %v", err)
			}
		})
	}
}

func TestDuplicateJSONMembersAreRejectedBeforeVerification(t *testing.T) {
	fixture := newVerifierFixture(t)
	header := mustJSON(t, fixture.dpopHeader)
	payload := []byte(fmt.Sprintf(`{"ath":%q,"ath":%q,"htm":"POST","htu":%q,"iat":%d,"jti":"abcdefghijklmnop"}`, tokenHash(fixture.externalToken), tokenHash(fixture.externalToken), testTarget, fixture.now.Unix()))
	proof := signES256Bytes(t, fixture.dpopKey, header, payload)
	if _, err := fixture.verifier.VerifySessionProof(proof, fixture.externalToken, "POST", testTarget); !errors.Is(err, errInvalid) {
		t.Fatalf("duplicate DPoP claim accepted: %v", err)
	}

	accessHeader := mustJSON(t, fixture.accessHeader)
	claims := mustJSON(t, fixture.accessClaims)
	duplicateClaims := append([]byte(`{"iss":"duplicate",`), claims[1:]...)
	token := signRS256Bytes(t, fixture.rsaKey, accessHeader, duplicateClaims)
	dpopClaims := cloneMap(fixture.dpopClaims)
	dpopClaims["ath"] = tokenHash(token)
	proof = signES256(t, fixture.dpopKey, fixture.dpopHeader, dpopClaims)
	if _, err := fixture.verifier.VerifyBootstrap(context.Background(), token, proof, "POST", testTarget); !errors.Is(err, errInvalid) {
		t.Fatalf("duplicate JWT claim accepted: %v", err)
	}
}

func TestJWKSUnknownKeyRefreshAndHardStaleFailure(t *testing.T) {
	fixture := newVerifierFixture(t)
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.keys = append(fixture.keys, testJWK{Key: &secondKey.PublicKey, KeyID: "issuer-key-2", Algorithm: "RS256", Use: "sig"})
	fixture.mu.Unlock()
	header := cloneMap(fixture.accessHeader)
	header["kid"] = "issuer-key-2"
	token := signRS256(t, secondKey, header, fixture.accessClaims)
	claims := cloneMap(fixture.dpopClaims)
	claims["ath"] = tokenHash(token)
	proof := signES256(t, fixture.dpopKey, fixture.dpopHeader, claims)
	if _, err := fixture.verifier.VerifyBootstrap(context.Background(), token, proof, "POST", testTarget); err != nil {
		t.Fatalf("rotated key not refreshed: %v", err)
	}
	fixture.mu.Lock()
	if fixture.requests != 2 {
		fixture.mu.Unlock()
		t.Fatalf("unknown kid caused %d requests, want initial fetch plus one refresh", fixture.requests)
	}
	fixture.mu.Unlock()

	fixture.now = fixture.now.Add(6 * time.Minute)
	fixture.mu.Lock()
	fixture.status = http.StatusServiceUnavailable
	fixture.mu.Unlock()
	if _, err := fixture.verifier.VerifyBootstrap(context.Background(), token, signES256(t, fixture.dpopKey, fixture.dpopHeader, map[string]any{
		"ath": tokenHash(token), "htm": "POST", "htu": testTarget, "iat": fixture.now.Unix(), "jti": "qrstuvwxyzABCDEF",
	}), "POST", testTarget); !errors.Is(err, errUnavailable) {
		t.Fatalf("hard-stale JWKS did not fail unavailable: %v", err)
	}
}

func TestJWKSRedirectAndMalformedSetsFailClosed(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		fixture := newVerifierFixture(t)
		fixture.verifier.Close()
		fixture.mu.Lock()
		fixture.redirect = fixture.server.URL + "/other"
		fixture.mu.Unlock()
		pool := x509.NewCertPool()
		pool.AddCert(fixture.server.Certificate())
		_, err := newVerifier(context.Background(), VerifierConfig{Issuer: testIssuer, Audience: testAudience, JWKS: JWKSConfig{
			URL: fixture.server.URL, Roots: pool, Algorithms: []jose.SignatureAlgorithm{jose.RS256}, SoftRefresh: time.Minute, HardMaxAge: 5 * time.Minute, RequestTimeout: time.Second,
		}}, func() time.Time { return fixture.now })
		if !errors.Is(err, errUnavailable) {
			t.Fatalf("redirect followed: %v", err)
		}
	})
	t.Run("duplicate-kid", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		encoded := rsaJWK(testJWK{Key: &key.PublicKey, KeyID: "same", Algorithm: "RS256", Use: "sig"})
		body := mustJSON(t, map[string]any{"keys": []any{encoded, encoded}})
		if _, err := parseJWKS(body, map[jose.SignatureAlgorithm]struct{}{jose.RS256: {}}); !errors.Is(err, errUnavailable) {
			t.Fatalf("duplicate kid accepted: %v", err)
		}
	})
	t.Run("forbidden-key-material-and-metadata", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		base := rsaJWK(testJWK{Key: &key.PublicKey, KeyID: "issuer-key", Algorithm: "RS256", Use: "sig"})
		for name, mutate := range map[string]func(map[string]any){
			"private":   func(jwk map[string]any) { jwk["d"] = "AQ" },
			"wrong-use": func(jwk map[string]any) { jwk["use"] = "enc" },
			"wrong-ops": func(jwk map[string]any) { jwk["key_ops"] = []string{"sign"} },
			"remote-url": func(jwk map[string]any) {
				jwk["jku"] = "https://attacker.invalid/jwks"
			},
		} {
			t.Run(name, func(t *testing.T) {
				jwk := cloneMap(base)
				mutate(jwk)
				body := mustJSON(t, map[string]any{"keys": []any{jwk}})
				if _, err := parseJWKS(body, map[jose.SignatureAlgorithm]struct{}{jose.RS256: {}}); !errors.Is(err, errUnavailable) {
					t.Fatalf("unsafe JWKS key accepted: %v", err)
				}
			})
		}
	})
}

func signRS256(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	return signRS256Bytes(t, key, mustJSON(t, header), mustJSON(t, claims))
}

func signRS256Bytes(t *testing.T, key *rsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	return signES256Bytes(t, key, mustJSON(t, header), mustJSON(t, claims))
}

func signES256Bytes(t *testing.T, key *ecdsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := encodedHeader + "." + encodedPayload
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

func publicECJWK(key *ecdsa.PrivateKey) map[string]any {
	return map[string]any{
		"crv": "P-256", "kty": "EC",
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
	}
}

func rsaJWK(key testJWK) map[string]any {
	exponent := big.NewInt(int64(key.Key.E)).Bytes()
	return map[string]any{
		"alg": key.Algorithm, "e": base64.RawURLEncoding.EncodeToString(exponent), "kid": key.KeyID,
		"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(key.Key.N.Bytes()), "use": key.Use,
	}
}

func (f *verifierFixture) dpopThumbprint(key *ecdsa.PrivateKey) string {
	f.t.Helper()
	_, value, err := parseDPoPPublicKey(mustJSON(f.t, publicECJWK(key)))
	if err != nil {
		f.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func cloneMap(input map[string]any) map[string]any {
	encoded, _ := json.Marshal(input)
	var output map[string]any
	_ = json.Unmarshal(encoded, &output)
	return output
}
