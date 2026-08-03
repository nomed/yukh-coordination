package clientauth

import (
	"context"
	"time"
)

const maxAccessTokenBytes = 8192

// BoundAccessToken is the closed external credential returned by an explicitly
// configured token source for RFC-0009 bootstrap.
type BoundAccessToken struct {
	credential string
	expiresAt  time.Time
}

func NewBoundAccessToken(credential string, expiresAt time.Time) (*BoundAccessToken, error) {
	if credential == "" || len(credential) > maxAccessTokenBytes || !asciiVisible(credential) || !validUTCmillisecond(expiresAt) {
		return nil, ErrInvalidCredential
	}
	return &BoundAccessToken{credential: credential, expiresAt: expiresAt}, nil
}

func (t *BoundAccessToken) ExpiresAt() time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.expiresAt
}

// Credential is restricted to the RFC-0009 bootstrap boundary. Callers must
// not retain, format or copy the returned token.
func (t *BoundAccessToken) Credential() string {
	if t == nil {
		return ""
	}
	return t.credential
}

func (*BoundAccessToken) String() string   { return "BoundAccessToken{REDACTED}" }
func (*BoundAccessToken) GoString() string { return "BoundAccessToken{REDACTED}" }

// ExternalTokenSource acquires one external access token explicitly bound to
// the supplied public DPoP key. It does not select or discover provider auth.
type ExternalTokenSource interface {
	Acquire(context.Context, PublicP256JWK) (*BoundAccessToken, error)
}
