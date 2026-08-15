package previewruntime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const previewBaseURI = "https://preview.coord.example"

func TestAuthorityAcceptsBoundedDynamicAgentNames(t *testing.T) {
	authority := NewAuthority()
	thumbprint := [sha256.Size]byte{1}
	if _, err := authority.Issue("agent-frontend-developer", thumbprint); err != nil {
		t.Fatalf("issue dynamic agent: %v", err)
	}
	for _, name := range []string{"agent-", "agent-A", "agent-a/../b", "worker-a", "agent-a_"} {
		if _, err := authority.Issue(name, thumbprint); err == nil {
			t.Fatalf("accepted invalid agent name %q", name)
		}
	}
}

func TestAuthorityBindsSingleUseBootstrapAndSessionProof(t *testing.T) {
	authority := NewAuthority()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := mustThumbprint(t, key)
	external, err := authority.Issue("agent-a", thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(authority, authority, allowAllPreview{}, previewApplication{}, httpapi.Config{PublicBaseURI: previewBaseURI, MaxStreamLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	bootstrapTarget := previewBaseURI + "/coordination/v1/sessions"
	bootstrap := request(http.MethodPost, bootstrapTarget, external.Credential, proof(t, key, external.Credential, http.MethodPost, bootstrapTarget, "abcdefghijklmnop"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, bootstrap)
	if response.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", response.Code, response.Body.String())
	}
	var session struct {
		Token string `json:"session_token"`
	}
	if json.Unmarshal(response.Body.Bytes(), &session) != nil || session.Token == "" {
		t.Fatalf("invalid session: %s", response.Body.String())
	}

	replayedBootstrap := httptest.NewRecorder()
	handler.ServeHTTP(replayedBootstrap, request(http.MethodPost, bootstrapTarget, external.Credential, bootstrap.Header.Get("DPoP")))
	if replayedBootstrap.Code != http.StatusUnauthorized {
		t.Fatalf("external token replay status=%d", replayedBootstrap.Code)
	}

	replayTarget := previewBaseURI + "/coordination/v1/channels/channel:test/transcripts/1/records"
	sessionProof := proof(t, key, session.Token, http.MethodGet, replayTarget, "qrstuvwxyzABCDEF")
	accepted := httptest.NewRecorder()
	handler.ServeHTTP(accepted, request(http.MethodGet, replayTarget, session.Token, sessionProof))
	if accepted.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	replayedSession := httptest.NewRecorder()
	handler.ServeHTTP(replayedSession, request(http.MethodGet, replayTarget, session.Token, sessionProof))
	if replayedSession.Code != http.StatusUnauthorized {
		t.Fatalf("session proof replay status=%d", replayedSession.Code)
	}
}

func TestAuthorityRejectsWrongProofKey(t *testing.T) {
	authority := NewAuthority()
	bound, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	external, err := authority.Issue("agent-b", mustThumbprint(t, bound))
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := httpapi.New(authority, authority, allowAllPreview{}, previewApplication{}, httpapi.Config{PublicBaseURI: previewBaseURI, MaxStreamLifetime: time.Minute})
	target := previewBaseURI + "/coordination/v1/sessions"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request(http.MethodPost, target, external.Credential, proof(t, attacker, external.Credential, http.MethodPost, target, "attackerProofJTI")))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key status=%d", response.Code)
	}
}

type allowAllPreview struct{}

func (allowAllPreview) Authorize(context.Context, httpapi.AccessRequest) (httpapi.Decision, error) {
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"profile":"local-preview"}`), ACLPolicyVersion: "local-v1", ACLPolicyDigest: "sha-256:1111111111111111111111111111111111111111111111111111111111111111", DecisionReceiptID: "local-decision"}, nil
}

type previewApplication struct{}

func (previewApplication) Append(context.Context, httpapi.AdmittedRequest, []byte) (httpapi.AppendResponse, error) {
	return httpapi.AppendResponse{}, nil
}
func (previewApplication) Replay(context.Context, httpapi.ReplayRequest) ([]byte, error) {
	return []byte(`{}`), nil
}
func (previewApplication) Stream(context.Context, httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	return make(chan httpapi.StreamItem), nil
}

func request(method, target, credential, dpop string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("Authorization", "DPoP "+credential)
	request.Header.Set("DPoP", dpop)
	if method == http.MethodGet {
		request.Header.Set("Accept", httpapi.TranscriptMediaType)
	}
	return request
}

func proof(t *testing.T, key *ecdsa.PrivateKey, credential, method, target, jti string) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &key.PublicKey})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(credential))
	claims, _ := json.Marshal(map[string]any{"ath": base64.RawURLEncoding.EncodeToString(digest[:]), "htm": method, "htu": target, "iat": time.Now().UTC().Unix(), "jti": jti})
	object, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func mustThumbprint(t *testing.T, key *ecdsa.PrivateKey) [sha256.Size]byte {
	t.Helper()
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	value, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var result [sha256.Size]byte
	copy(result[:], value)
	return result
}
