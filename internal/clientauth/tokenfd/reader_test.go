package tokenfd

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
)

func TestReaderAcceptsOneBoundUnexpiredCompactJWT(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	jwk := testJWK(t, 1)
	token := compactToken(t, map[string]any{
		"exp": now.Add(time.Minute).Unix(),
		"cnf": map[string]string{"jkt": thumbprint(jwk)},
	})
	t.Setenv("YUKH_BOOTSTRAP_TOKEN", "ambient-token-must-not-be-used")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/ambient")
	descriptor := tokenDescriptor(t, token)
	defer descriptor.Close()

	reader := &Reader{now: func() time.Time { return now }}
	bound, err := reader.ReadBoundAccessToken(context.Background(), descriptor, jwk)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	if bound.Credential() != token || !bound.ExpiresAt().Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected bound token: %#v", bound)
	}
	if _, err := descriptor.Stat(); err != nil {
		t.Fatalf("reader closed caller-owned descriptor: %v", err)
	}
}

func TestReaderRejectsMalformedExpiredAndWronglyBoundTokens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	jwk := testJWK(t, 1)
	other := testJWK(t, 2)
	tests := []struct {
		name  string
		token string
	}{
		{"malformed", "not-a-jwt"},
		{"missing-exp", compactToken(t, map[string]any{"cnf": map[string]string{"jkt": thumbprint(jwk)}})},
		{"expired", compactToken(t, map[string]any{"exp": now.Add(-time.Second).Unix(), "cnf": map[string]string{"jkt": thumbprint(jwk)}})},
		{"wrong-binding", compactToken(t, map[string]any{"exp": now.Add(time.Minute).Unix(), "cnf": map[string]string{"jkt": thumbprint(other)}})},
		{"unsecured-header", compactTokenWithHeader(t, map[string]any{"alg": "none"}, map[string]any{"exp": now.Add(time.Minute).Unix(), "cnf": map[string]string{"jkt": thumbprint(jwk)}})},
		{"duplicate-claim", rawCompactToken(`{"alg":"RS256"}`, `{"exp":1700000060,"exp":1700000061,"cnf":{"jkt":"`+thumbprint(jwk)+`"}}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := tokenDescriptor(t, test.token)
			defer descriptor.Close()
			reader := &Reader{now: func() time.Time { return now }}
			bound, err := reader.ReadBoundAccessToken(context.Background(), descriptor, jwk)
			if !errors.Is(err, clientauth.ErrExternalToken) || bound != nil {
				t.Fatalf("accepted invalid token: token=%#v err=%v", bound, err)
			}
		})
	}
}

func TestReaderHasNoAmbientOrUnboundedFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	jwk := testJWK(t, 1)
	ambient := compactToken(t, map[string]any{
		"exp": now.Add(time.Minute).Unix(),
		"cnf": map[string]string{"jkt": thumbprint(jwk)},
	})
	t.Setenv("YUKH_BOOTSTRAP_TOKEN", ambient)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/ambient")
	reader := &Reader{now: func() time.Time { return now }}

	empty := tokenDescriptor(t, "")
	defer empty.Close()
	if token, err := reader.ReadBoundAccessToken(context.Background(), empty, jwk); !errors.Is(err, clientauth.ErrExternalToken) || token != nil {
		t.Fatalf("ambient token was used: token=%#v err=%v", token, err)
	}
	oversized := tokenDescriptor(t, strings.Repeat("a", maximumTokenBytes+1))
	defer oversized.Close()
	if token, err := reader.ReadBoundAccessToken(context.Background(), oversized, jwk); !errors.Is(err, clientauth.ErrExternalToken) || token != nil {
		t.Fatalf("oversized descriptor token was accepted: token=%#v err=%v", token, err)
	}
	if token, err := reader.ReadBoundAccessToken(context.Background(), os.Stdin, jwk); !errors.Is(err, clientauth.ErrExternalToken) || token != nil {
		t.Fatalf("standard input was accepted as a token descriptor: token=%#v err=%v", token, err)
	}
}

func testJWK(t *testing.T, scalar byte) clientauth.PublicP256JWK {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{scalar})
	jwk, err := clientauth.NewPublicP256JWK(x.FillBytes(make([]byte, 32)), y.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return jwk
}

func compactToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	return compactTokenWithHeader(t, map[string]any{"alg": "RS256", "typ": "at+jwt"}, claims)
}

func compactTokenWithHeader(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	headerRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return rawCompactToken(string(headerRaw), string(claimsRaw))
}

func rawCompactToken(header, claims string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))
}

func thumbprint(jwk clientauth.PublicP256JWK) string {
	value := jwk.Thumbprint()
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func tokenDescriptor(t *testing.T, token string) *os.File {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.WriteString(token); err != nil {
		_ = read.Close()
		_ = write.Close()
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		_ = read.Close()
		t.Fatal(err)
	}
	return read
}
