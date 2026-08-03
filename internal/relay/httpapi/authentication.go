package httpapi

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnauthenticated           = errors.New("httpapi: unauthenticated")
	ErrAuthenticationUnavailable = errors.New("httpapi: authentication unavailable")
)

// BootstrapAuthentication is the closed request material for exchanging one
// external, sender-constrained access token for one relay session.
type BootstrapAuthentication struct {
	credential string
	proof      string
	method     string
	targetURI  string
}

func (a BootstrapAuthentication) Credential() string { return a.credential }
func (a BootstrapAuthentication) Proof() string      { return a.proof }
func (a BootstrapAuthentication) Method() string     { return a.method }
func (a BootstrapAuthentication) TargetURI() string  { return a.targetURI }
func (BootstrapAuthentication) String() string       { return "BootstrapAuthentication{REDACTED}" }
func (BootstrapAuthentication) GoString() string     { return "BootstrapAuthentication{REDACTED}" }

// SessionAuthentication is the closed request material for authenticating one
// relay-issued, proof-bound session capability.
type SessionAuthentication struct {
	credential string
	proof      string
	method     string
	targetURI  string
}

func (a SessionAuthentication) Credential() string { return a.credential }
func (a SessionAuthentication) Proof() string      { return a.proof }
func (a SessionAuthentication) Method() string     { return a.method }
func (a SessionAuthentication) TargetURI() string  { return a.targetURI }
func (SessionAuthentication) String() string       { return "SessionAuthentication{REDACTED}" }
func (SessionAuthentication) GoString() string     { return "SessionAuthentication{REDACTED}" }

type IssuedSession struct {
	SessionToken          string
	ParticipantInstanceID string
	SessionEpoch          uint64
	IssuedAt              time.Time
	ExpiresAt             time.Time
}

type SessionBootstrapper interface {
	Bootstrap(context.Context, BootstrapAuthentication) (IssuedSession, error)
}

type Authenticator interface {
	Authenticate(context.Context, SessionAuthentication) (Identity, error)
}

func newBootstrapAuthentication(credential, proof, method, targetURI string) BootstrapAuthentication {
	return BootstrapAuthentication{credential: credential, proof: proof, method: method, targetURI: targetURI}
}

func newSessionAuthentication(credential, proof, method, targetURI string) SessionAuthentication {
	return SessionAuthentication{credential: credential, proof: proof, method: method, targetURI: targetURI}
}
