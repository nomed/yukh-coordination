package clientauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

type clock func() time.Time
type identifierSource func() (uuid.UUID, error)

// Authorizer loads one session only for the duration of a request and creates
// a fresh proof over the normalized public target.
type Authorizer struct {
	store   CredentialStore
	profile string
	now     clock
	newJTI  identifierSource
}

func NewAuthorizer(store CredentialStore, profile string) (*Authorizer, error) {
	if store == nil || validateProfile(profile) != nil {
		return nil, ErrInvalidCredential
	}
	return &Authorizer{store: store, profile: profile, now: time.Now, newJTI: uuid.NewV7}, nil
}

func (a *Authorizer) Authorize(request *http.Request) error {
	if a == nil || a.store == nil || a.now == nil || a.newJTI == nil || request == nil || request.URL == nil || request.Method == "" || request.Method != strings.ToUpper(request.Method) || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil || request.URL.Fragment != "" || len(request.Header.Values("Authorization")) != 0 || len(request.Header.Values("DPoP")) != 0 || len(request.Header.Values("Cookie")) != 0 {
		return ErrInvalidCredential
	}
	credentials, err := a.store.Load(request.Context(), a.profile)
	if err != nil {
		return sanitizeStoreError(err)
	}
	if !validCredentials(credentials) {
		return ErrCredentialStore
	}
	now := a.now().UTC()
	if !now.Before(credentials.expiresAt) {
		return ErrCredentialMissing
	}
	target := *request.URL
	target.RawQuery = ""
	target.ForceQuery = false
	target.Fragment = ""
	proof, err := createProof(credentials, request.Method, target.String(), now, a.newJTI)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "DPoP "+credentials.sessionToken)
	request.Header.Set("DPoP", proof)
	return nil
}

type proofClaims struct {
	ATH string `json:"ath"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
}

func createProof(credentials *SessionCredentials, method, target string, now time.Time, newJTI identifierSource) (string, error) {
	jti, err := newJTI()
	if err != nil || jti.Version() != 7 {
		return "", ErrInvalidCredential
	}
	digest := sha256.Sum256([]byte(credentials.sessionToken))
	claims, err := json.Marshal(proofClaims{ATH: base64.RawURLEncoding.EncodeToString(digest[:]), HTM: method, HTU: target, IAT: now.Unix(), JTI: jti.String()})
	if err != nil {
		return "", ErrInvalidCredential
	}
	options := (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &credentials.privateKey.PublicKey})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: credentials.privateKey}, options)
	if err != nil {
		return "", ErrInvalidCredential
	}
	object, err := signer.Sign(claims)
	if err != nil {
		return "", ErrInvalidCredential
	}
	proof, err := object.CompactSerialize()
	if err != nil || len(proof) > 16_384 {
		return "", ErrInvalidCredential
	}
	return proof, nil
}

var _ interface{ Authorize(*http.Request) error } = (*Authorizer)(nil)
