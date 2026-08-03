// Package clientauth provides the RFC-0013 client-side credential and DPoP
// boundary. It deliberately contains no persistent storage implementation.
package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

const (
	credentialSpecVersion = "0.1"
	maxSafeInteger        = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidCredential = errors.New("client authentication: invalid credential")
	ErrCredentialStore   = errors.New("client authentication: credential store unavailable")
	ErrCredentialMissing = errors.New("client authentication: credential missing")
)

// CredentialStore is the mandatory custody boundary. Implementations must use
// an explicitly selected operating-system credential store and must never fall
// back to plaintext files. Tests supply an in-memory fake.
type CredentialStore interface {
	Load(context.Context, string) (*SessionCredentials, error)
	Save(context.Context, string, *SessionCredentials) error
	Delete(context.Context, string) error
}

// SessionCredentials is one immutable proof-bound relay session. Secret fields
// are intentionally inaccessible outside this package.
type SessionCredentials struct {
	specVersion           string
	participantInstanceID string
	sessionEpoch          uint64
	sessionToken          string
	expiresAt             time.Time
	privateKey            *ecdsa.PrivateKey
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrInvalidCredential
	}
	return key, nil
}

func NewSessionCredentials(participantInstanceID string, sessionEpoch uint64, sessionToken string, expiresAt time.Time, privateKey *ecdsa.PrivateKey) (*SessionCredentials, error) {
	participant, participantErr := uuid.Parse(participantInstanceID)
	decodedToken, tokenErr := base64.RawURLEncoding.Strict().DecodeString(sessionToken)
	if participantErr != nil || participant.Version() != 7 || participant.String() != participantInstanceID || sessionEpoch == 0 || sessionEpoch > maxSafeInteger || tokenErr != nil || len(sessionToken) != 43 || len(decodedToken) != 32 || expiresAt.Location() != time.UTC || !expiresAt.Equal(expiresAt.Truncate(time.Millisecond)) || !validPrivateKey(privateKey) {
		return nil, ErrInvalidCredential
	}
	return &SessionCredentials{
		specVersion:           credentialSpecVersion,
		participantInstanceID: participantInstanceID,
		sessionEpoch:          sessionEpoch,
		sessionToken:          sessionToken,
		expiresAt:             expiresAt,
		privateKey:            clonePrivateKey(privateKey),
	}, nil
}

func (c *SessionCredentials) SpecVersion() string {
	if c == nil {
		return ""
	}
	return c.specVersion
}
func (c *SessionCredentials) ParticipantInstanceID() string {
	if c == nil {
		return ""
	}
	return c.participantInstanceID
}
func (c *SessionCredentials) SessionEpoch() uint64 {
	if c == nil {
		return 0
	}
	return c.sessionEpoch
}
func (c *SessionCredentials) ExpiresAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.expiresAt
}
func (*SessionCredentials) String() string   { return "SessionCredentials{REDACTED}" }
func (*SessionCredentials) GoString() string { return "SessionCredentials{REDACTED}" }

func (c *SessionCredentials) clone() (*SessionCredentials, error) {
	if !validCredentials(c) {
		return nil, ErrInvalidCredential
	}
	return &SessionCredentials{c.specVersion, c.participantInstanceID, c.sessionEpoch, c.sessionToken, c.expiresAt, clonePrivateKey(c.privateKey)}, nil
}

func validCredentials(c *SessionCredentials) bool {
	if c == nil {
		return false
	}
	validated, err := NewSessionCredentials(c.participantInstanceID, c.sessionEpoch, c.sessionToken, c.expiresAt, c.privateKey)
	return err == nil && c.specVersion == validated.specVersion
}

func validPrivateKey(key *ecdsa.PrivateKey) bool {
	if key == nil || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
		return false
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	return x.Cmp(key.X) == 0 && y.Cmp(key.Y) == 0
}

func clonePrivateKey(key *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	d := new(big.Int).Set(key.D)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}

func sanitizeStoreError(err error) error {
	if errors.Is(err, ErrCredentialMissing) {
		return ErrCredentialMissing
	}
	return ErrCredentialStore
}

func validateProfile(profile string) error {
	if profile == "" || len(profile) > 128 {
		return ErrInvalidCredential
	}
	for _, r := range profile {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ErrInvalidCredential
		}
	}
	return nil
}

var _ fmt.Stringer = (*SessionCredentials)(nil)
