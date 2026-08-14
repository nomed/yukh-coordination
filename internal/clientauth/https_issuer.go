package clientauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	sessionMediaType      = "application/yukh-session+json;version=0.1"
	maxSessionBodyBytes   = 8 << 10
	bootstrapSessionRoute = "/coordination/v1/sessions"
)

// HTTPSessionIssuer exchanges an explicitly supplied external token for a
// proof-bound relay session. It has no provider discovery or credential custody.
type HTTPSessionIssuer struct {
	base   *url.URL
	http   *http.Client
	now    clock
	newJTI identifierSource
}

type sessionDocument struct {
	ExpiresAt             string `json:"expires_at"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	SessionEpoch          uint64 `json:"session_epoch"`
	SessionToken          string `json:"session_token"`
	SpecVersion           string `json:"specversion"`
	TokenType             string `json:"token_type"`
}

// NewHTTPSessionIssuer creates a fail-closed HTTPS bootstrap client. The
// supplied transport is used only for the exact configured relay authority.
func NewHTTPSessionIssuer(baseURI string, transport http.RoundTripper) (*HTTPSessionIssuer, error) {
	base, err := parseBootstrapBaseURI(baseURI)
	if err != nil || transport == nil {
		return nil, ErrInvalidCredential
	}
	return &HTTPSessionIssuer{
		base: base,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now:    time.Now,
		newJTI: uuid.NewV7,
	}, nil
}

func (i *HTTPSessionIssuer) Issue(ctx context.Context, token *BoundAccessToken, signer ProofSigner) (*IssuedSession, error) {
	if i == nil || i.base == nil || i.http == nil || i.now == nil || i.newJTI == nil || ctx == nil || token == nil || nilInterface(signer) {
		return nil, ErrExternalToken
	}
	if !token.ExpiresAt().After(i.now().UTC()) {
		return nil, ErrExternalToken
	}
	target := *i.base
	target.Path += bootstrapSessionRoute
	target.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		return nil, ErrExternalToken
	}
	proof, err := bootstrapProof(ctx, token, signer, request.Method, request.URL.String(), i.now().UTC(), i.newJTI)
	if err != nil {
		return nil, ErrExternalToken
	}
	request.Header.Set("Authorization", "DPoP "+token.Credential())
	request.Header.Set("DPoP", proof)

	response, err := i.http.Do(request)
	if err != nil {
		return nil, ErrExternalToken
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.String() != request.URL.String() || response.StatusCode != http.StatusCreated ||
		response.Header.Get("Content-Type") != sessionMediaType || !strings.HasPrefix(response.Header.Get("Cache-Control"), "no-store") ||
		response.Header.Get("Pragma") != "no-cache" || len(response.Header.Values("Set-Cookie")) != 0 {
		return nil, ErrExternalToken
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSessionBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxSessionBodyBytes {
		return nil, ErrExternalToken
	}
	issued, err := decodeIssuedSession(body, i.now().UTC().Truncate(time.Millisecond))
	if err != nil {
		return nil, ErrExternalToken
	}
	return issued, nil
}

func parseBootstrapBaseURI(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || strings.HasSuffix(parsed.Path, "/") {
		return nil, ErrInvalidCredential
	}
	return parsed, nil
}

func bootstrapProof(ctx context.Context, token *BoundAccessToken, signer ProofSigner, method, target string, now time.Time, newJTI identifierSource) (string, error) {
	if token == nil || signer.KeyReference() == "" || !validProofMethod(method) || now.Location() != time.UTC || newJTI == nil {
		return "", ErrInvalidCredential
	}
	jwk, err := signer.PublicJWK()
	if err != nil {
		return "", ErrProofSigner
	}
	publicKey, err := jwk.publicKey()
	if err != nil {
		return "", ErrProofSigner
	}
	jti, err := newJTI()
	if err != nil || jti.Version() != 7 {
		return "", ErrInvalidCredential
	}
	x, y := jwk.Coordinates()
	header, err := json.Marshal(proofHeader{Algorithm: "ES256", JWK: proofHeaderJWK{Curve: "P-256", KeyType: "EC", X: base64.RawURLEncoding.EncodeToString(x[:]), Y: base64.RawURLEncoding.EncodeToString(y[:])}, Type: "dpop+jwt"})
	if err != nil {
		return "", ErrInvalidCredential
	}
	digest := sha256.Sum256([]byte(token.Credential()))
	claims, err := json.Marshal(proofClaims{ATH: base64.RawURLEncoding.EncodeToString(digest[:]), HTM: method, HTU: target, IAT: now.Unix(), JTI: jti.String()})
	if err != nil {
		return "", ErrInvalidCredential
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	if len(input) > maxSigningInputBytes {
		return "", ErrInvalidCredential
	}
	signature, err := signer.SignES256(ctx, []byte(input))
	if err != nil || ctx.Err() != nil || !validSignature(publicKey, []byte(input), signature) {
		return "", ErrProofSigner
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature[:]), nil
}

func decodeIssuedSession(body []byte, issuedAt time.Time) (*IssuedSession, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var document sessionDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.SpecVersion != "0.1" || document.TokenType != "DPoP" {
		return nil, ErrInvalidCredential
	}
	expiresAt, err := time.Parse("2006-01-02T15:04:05.000Z", document.ExpiresAt)
	if err != nil || expiresAt.Format("2006-01-02T15:04:05.000Z") != document.ExpiresAt {
		return nil, ErrInvalidCredential
	}
	return NewIssuedSession(document.ParticipantInstanceID, document.SessionEpoch, document.SessionToken, issuedAt, expiresAt)
}

var _ SessionIssuer = (*HTTPSessionIssuer)(nil)
