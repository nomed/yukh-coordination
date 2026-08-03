package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type clock func() time.Time
type identifierSource func() (uuid.UUID, error)

// Authorizer loads one session and opens its exact signer only for the duration
// of a request. It creates and locally verifies a fresh proof before mutation.
type Authorizer struct {
	store       CredentialStore
	signerStore ProofSignerStore
	profile     string
	now         clock
	newJTI      identifierSource
}

func NewAuthorizer(store CredentialStore, signerStore ProofSignerStore, profile string) (*Authorizer, error) {
	if nilInterface(store) || nilInterface(signerStore) || validateProfile(profile) != nil {
		return nil, ErrInvalidCredential
	}
	return &Authorizer{store: store, signerStore: signerStore, profile: profile, now: time.Now, newJTI: uuid.NewV7}, nil
}

func (a *Authorizer) Authorize(request *http.Request) error {
	if a == nil || nilInterface(a.store) || nilInterface(a.signerStore) || a.now == nil || a.newJTI == nil || request == nil || request.URL == nil || request.Method == "" || request.Method != strings.ToUpper(request.Method) || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || request.URL.Fragment != "" || len(request.Header.Values("Authorization")) != 0 || len(request.Header.Values("DPoP")) != 0 || len(request.Header.Values("Cookie")) != 0 {
		return ErrInvalidCredential
	}
	stored, err := a.store.Load(request.Context(), a.profile)
	if err != nil {
		return sanitizeStoreError(err)
	}
	record, err := stored.Record()
	if err != nil || !stored.Revision().valid() || stored.Revision().absent {
		return ErrCredentialStore
	}
	now := a.now().UTC()
	if !now.Before(record.expiresAt) {
		return ErrCredentialMissing
	}

	signer, err := a.signerStore.Open(request.Context(), record.proofKeyReference)
	if err != nil {
		return sanitizeSignerError(err)
	}
	if nilInterface(signer) || signer.KeyReference() != record.proofKeyReference {
		return ErrProofSigner
	}
	jwk, err := signer.PublicJWK()
	if err != nil {
		return ErrProofSigner
	}
	publicKey, err := jwk.publicKey()
	if err != nil {
		return ErrProofSigner
	}
	if !jwk.equalThumbprint(record.proofJWKThumbprint) {
		return ErrProofKeyMissing
	}

	target := *request.URL
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	proof, err := createProof(request.Context(), record, signer, jwk, publicKey, request.Method, target.String(), now, a.newJTI)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "DPoP "+record.sessionToken)
	request.Header.Set("DPoP", proof)
	return nil
}

type proofHeader struct {
	Algorithm string         `json:"alg"`
	JWK       proofHeaderJWK `json:"jwk"`
	Type      string         `json:"typ"`
}

type proofHeaderJWK struct {
	Curve   string `json:"crv"`
	KeyType string `json:"kty"`
	X       string `json:"x"`
	Y       string `json:"y"`
}

type proofClaims struct {
	ATH string `json:"ath"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
}

func createProof(ctx context.Context, record *SessionRecord, signer ProofSigner, jwk PublicP256JWK, publicKey *ecdsa.PublicKey, method, target string, now time.Time, newJTI identifierSource) (string, error) {
	jti, err := newJTI()
	if err != nil || jti.Version() != 7 {
		return "", ErrInvalidCredential
	}
	tokenDigest := sha256.Sum256([]byte(record.sessionToken))
	header, err := json.Marshal(proofHeader{Algorithm: "ES256", JWK: proofHeaderJWK{Curve: "P-256", KeyType: "EC", X: base64.RawURLEncoding.EncodeToString(jwk.x[:]), Y: base64.RawURLEncoding.EncodeToString(jwk.y[:])}, Type: "dpop+jwt"})
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

func sanitizeSignerError(err error) error {
	if errors.Is(err, ErrProofKeyMissing) {
		return ErrProofKeyMissing
	}
	return ErrProofSigner
}

var _ interface{ Authorize(*http.Request) error } = (*Authorizer)(nil)
