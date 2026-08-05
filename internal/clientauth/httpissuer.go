package clientauth

import (
	"context"
	"crypto/ecdsa"
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

// HTTPIssuer implements SessionIssuer over an exact, closed HTTPS boundary.
type HTTPIssuer struct {
	baseURI    string
	httpClient *http.Client
	now        clock
	newJTI     identifierSource
}

// NewHTTPIssuer creates a new HTTPIssuer. It validates the base URI.
func NewHTTPIssuer(baseURI string, httpClient *http.Client) (*HTTPIssuer, error) {
	if httpClient == nil {
		httpClient = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 10 * time.Second,
		}
	}
	parsed, err := url.Parse(baseURI)
	if err != nil || parsed.String() != baseURI || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrInvalidCredential
	}
	return &HTTPIssuer{baseURI: strings.TrimSuffix(baseURI, "/"), httpClient: httpClient, now: time.Now, newJTI: uuid.NewV7}, nil
}

type sessionDocument struct {
	ExpiresAt             string `json:"expires_at"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	SessionEpoch          uint64 `json:"session_epoch"`
	SessionToken          string `json:"session_token"`
	SpecVersion           string `json:"spec_version"`
	TokenType             string `json:"token_type"`
}

func (h *HTTPIssuer) Issue(ctx context.Context, external *BoundAccessToken, signer ProofSigner) (*IssuedSession, error) {
	if h == nil || ctx == nil || external == nil || nilInterface(signer) {
		return nil, ErrInvalidCredential
	}
	targetURI := h.baseURI + "/coordination/v1/sessions"
	parsed, _ := url.Parse(targetURI)
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, ErrInvalidCredential
	}

	jwk, err := signer.PublicJWK()
	if err != nil {
		return nil, ErrProofSigner
	}
	publicKey, err := jwk.publicKey()
	if err != nil {
		return nil, ErrProofSigner
	}

	now := h.now().UTC()
	proof, err := createBootstrapProof(ctx, external.Credential(), signer, jwk, publicKey, http.MethodPost, targetURI, now, h.newJTI)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURI, nil)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	request.Header.Set("Authorization", "DPoP "+external.Credential())
	request.Header.Set("DPoP", proof)
	request.Header.Set("Accept", "application/yukh-session+json;version=0.1")

	response, err := h.httpClient.Do(request)
	if err != nil {
		return nil, ErrExternalToken
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return nil, ErrExternalToken
	}

	contentType := response.Header.Get("Content-Type")
	if contentType != "application/yukh-session+json;version=0.1" {
		return nil, ErrExternalToken
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil || len(body) >= 8192 {
		return nil, ErrExternalToken
	}

	var doc sessionDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, ErrExternalToken
	}

	if doc.SpecVersion != "0.1" || doc.TokenType != "DPoP" || doc.ParticipantInstanceID == "" || doc.SessionEpoch == 0 || doc.SessionToken == "" {
		return nil, ErrExternalToken
	}
	participant, err := uuid.Parse(doc.ParticipantInstanceID)
	if err != nil || participant.Version() != 7 || participant.String() != doc.ParticipantInstanceID {
		return nil, ErrExternalToken
	}
	expiresAt, err := time.Parse("2006-01-02T15:04:05.000Z", doc.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC {
		return nil, ErrExternalToken
	}
	if !expiresAt.After(now) || expiresAt.Sub(now) > 15*time.Minute {
		return nil, ErrExternalToken
	}

	issued, err := NewIssuedSession(doc.ParticipantInstanceID, doc.SessionEpoch, doc.SessionToken, now, expiresAt)
	if err != nil {
		return nil, ErrExternalToken
	}
	return issued, nil
}

func createBootstrapProof(ctx context.Context, token string, signer ProofSigner, jwk PublicP256JWK, publicKey *ecdsa.PublicKey, method, target string, now time.Time, newJTI identifierSource) (string, error) {
	jti, err := newJTI()
	if err != nil || jti.Version() != 7 {
		return "", ErrInvalidCredential
	}
	tokenDigest := sha256.Sum256([]byte(token))
	x, y := jwk.Coordinates()
	header, err := json.Marshal(proofHeader{Algorithm: "ES256", JWK: proofHeaderJWK{Curve: "P-256", KeyType: "EC", X: base64.RawURLEncoding.EncodeToString(x[:]), Y: base64.RawURLEncoding.EncodeToString(y[:])}, Type: "dpop+jwt"})
	if err != nil {
		return "", ErrInvalidCredential
	}
	claims, err := json.Marshal(proofClaims{ATH: base64.RawURLEncoding.EncodeToString(tokenDigest[:]), HTM: method, HTU: target, IAT: now.Unix(), JTI: jti.String()})
	if err != nil {
		return "", ErrInvalidCredential
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	if len(signingInput) > maxSigningInputBytes {
		return "", ErrInvalidCredential
	}
	signature, err := signer.SignES256(ctx, []byte(signingInput))
	if err != nil {
		return "", ErrProofSigner
	}
	if ctx.Err() != nil {
		return "", ErrProofSigner
	}
	if !validSignature(publicKey, []byte(signingInput), signature) {
		return "", ErrProofSigner
	}
	proof := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature[:])
	if len(proof) > 16_384 {
		return "", ErrInvalidCredential
	}
	return proof, nil
}
