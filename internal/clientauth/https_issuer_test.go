package clientauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func TestHTTPSessionIssuerExchangesExactBoundRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	_, signer := testSession(t, now)
	token, err := NewBoundAccessToken("header.payload.signature", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != bootstrapSessionRoute || request.ContentLength != 0 ||
			request.Header.Get("Authorization") != "DPoP "+token.Credential() || request.Header.Get("Cookie") != "" {
			t.Fatalf("unexpected bootstrap request: %#v", request)
		}
		verifier := identity.NewDPoPVerifier()
		target := "https://" + request.Host + request.URL.RequestURI()
		if _, err := verifier.Verify(request.Header.Get("DPoP"), token.Credential(), request.Method, target); err != nil {
			t.Fatalf("invalid bound proof: %v", err)
		}
		w.Header().Set("Content-Type", sessionMediaType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(sessionDocument{
			ExpiresAt:             now.Add(time.Minute).Format("2006-01-02T15:04:05.000Z"),
			ParticipantInstanceID: testParticipant,
			SessionEpoch:          7,
			SessionToken:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			SpecVersion:           "0.1",
			TokenType:             "DPoP",
		})
	}))
	defer server.Close()

	issuer, err := NewHTTPSessionIssuer(server.URL, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	issuer.newJTI = func() (uuid.UUID, error) { return uuid.MustParse("01890f3e-7b00-7000-8000-000000000010"), nil }
	issued, err := issuer.Issue(context.Background(), token, signer)
	if err != nil {
		t.Fatal(err)
	}
	if issued.participant != testParticipant || issued.epoch != 7 || issued.token != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected issued session: %#v", issued)
	}
}

func TestHTTPSessionIssuerRejectsRedirectAndMalformedResponses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, signer := testSession(t, now)
	token, err := NewBoundAccessToken("header.payload.signature", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://relay.invalid/elsewhere", http.StatusFound)
		}},
		{"wrong-media", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		}},
		{"invalid-session", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", sessionMediaType)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"expires_at":"2026-01-01T00:01:00.000Z","participant_instance_id":"not-a-uuid","session_epoch":1,"session_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","specversion":"0.1","token_type":"DPoP"}`))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			issuer, err := NewHTTPSessionIssuer(server.URL, server.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			issuer.now = func() time.Time { return now }
			issuer.newJTI = func() (uuid.UUID, error) { return uuid.MustParse("01890f3e-7b00-7000-8000-000000000011"), nil }
			if _, err := issuer.Issue(context.Background(), token, signer); err != ErrExternalToken {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestHTTPSessionIssuerRejectsExpiredTokenBeforeNetwork(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, signer := testSession(t, now)
	token, err := NewBoundAccessToken("header.payload.signature", now)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer server.Close()
	issuer, err := NewHTTPSessionIssuer(server.URL, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	if _, err := issuer.Issue(context.Background(), token, signer); err != ErrExternalToken || calls != 0 {
		t.Fatalf("expired token reached relay: err=%v calls=%d", err, calls)
	}
}
