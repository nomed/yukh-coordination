package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type testIssuerSigner struct {
	reference string
	key       *ecdsa.PrivateKey
	jwk       PublicP256JWK
}

func newTestIssuerSigner(t *testing.T) *testIssuerSigner {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var x, y [32]byte
	private.X.FillBytes(x[:])
	private.Y.FillBytes(y[:])
	jwk, _ := NewPublicP256JWK(x[:], y[:])
	return &testIssuerSigner{reference: "test-key", key: private, jwk: jwk}
}

func (s *testIssuerSigner) KeyReference() string { return s.reference }
func (s *testIssuerSigner) PublicJWK() (PublicP256JWK, error) { return s.jwk, nil }
func (s *testIssuerSigner) SignES256(_ context.Context, input []byte) ([64]byte, error) {
	digest := sha256.Sum256(input)
	r, sInt, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return [64]byte{}, err
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	sInt.FillBytes(signature[32:])
	return signature, nil
}

func TestHTTPIssuerIssue(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt := now.Add(10 * time.Minute)
	participant := uuid.Must(uuid.NewV7())

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/coordination/v1/sessions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "DPoP external-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("DPoP") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/yukh-session+json;version=0.1")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(sessionDocument{
			ExpiresAt:             expiresAt.Format("2006-01-02T15:04:05.000Z"),
			ParticipantInstanceID: participant.String(),
			SessionEpoch:          42,
			SessionToken:          "jhxeBktt2nliAX1t6s9lggsYVl5SfObUcE0erK6JrjY",
			SpecVersion:           "0.1",
			TokenType:             "DPoP",
		})
	}))
	defer server.Close()

	issuer, err := NewHTTPIssuer(server.URL, server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	issuer.now = func() time.Time { return now }

	external, _ := NewBoundAccessToken("external-token", expiresAt)
	signer := newTestIssuerSigner(t)

	issued, err := issuer.Issue(context.Background(), external, signer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issued.participant != participant.String() || issued.epoch != 42 || issued.token != "jhxeBktt2nliAX1t6s9lggsYVl5SfObUcE0erK6JrjY" {
		t.Errorf("unexpected issued session: %+v", issued)
	}
}

func TestHTTPIssuerNegative(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	expiresAt := now.Add(10 * time.Minute)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bad-media-type") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(sessionDocument{
				ExpiresAt:             expiresAt.Format("2006-01-02T15:04:05.000Z"),
				ParticipantInstanceID: uuid.Must(uuid.NewV7()).String(),
				SessionEpoch:          42,
				SessionToken:          "jhxeBktt2nliAX1t6s9lggsYVl5SfObUcE0erK6JrjY",
				SpecVersion:           "0.1",
				TokenType:             "DPoP",
			})
			return
		}
		if strings.Contains(r.URL.Path, "bad-status") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	issuer, _ := NewHTTPIssuer(server.URL, server.Client())
	issuer.now = func() time.Time { return now }

	external, _ := NewBoundAccessToken("external-token", expiresAt)
	signer := newTestIssuerSigner(t)

	// Test bad status
	issuer.baseURI = server.URL + "/bad-status"
	if _, err := issuer.Issue(context.Background(), external, signer); err == nil {
		t.Error("expected error for bad status")
	}

	// Test bad media type
	issuer.baseURI = server.URL + "/bad-media-type"
	if _, err := issuer.Issue(context.Background(), external, signer); err == nil {
		t.Error("expected error for bad media type")
	}
}
