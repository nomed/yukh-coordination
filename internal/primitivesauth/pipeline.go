// Package primitivesauth implements the RFC-0017 two-phase authorization
// boundary independently from the relay and from concrete identity providers.
package primitivesauth

import (
	"context"
	"errors"
	"regexp"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

var (
	ErrInvalidArgument        = errors.New("primitives authorization: invalid argument")
	ErrUnauthenticated        = errors.New("primitives authorization: unauthenticated")
	ErrAccessDenied           = errors.New("primitives authorization: access denied")
	ErrInvalidCapability      = errors.New("primitives authorization: invalid capability")
	ErrTemporarilyUnavailable = errors.New("primitives authorization: temporarily unavailable")
)

type Action string

const (
	NonceConsume Action = "coordination.nonce.consume"
	LeaseAcquire Action = "coordination.lease.acquire"
	LeaseInspect Action = "coordination.lease.inspect"
	LeaseRenew   Action = "coordination.lease.renew"
	LeaseRelease Action = "coordination.lease.release"
)

func validAction(action Action) bool {
	switch action {
	case NonceConsume, LeaseAcquire, LeaseInspect, LeaseRenew, LeaseRelease:
		return true
	default:
		return false
	}
}

type RequestAuthentication struct {
	credential string
	proof      string
	method     string
	targetURI  string
}

func NewRequestAuthentication(credential, proof, method, targetURI string) (RequestAuthentication, error) {
	if credential == "" || len(credential) > 8192 || proof == "" || len(proof) > 16384 || method != "POST" || len(targetURI) < 9 || len(targetURI) > 4096 {
		return RequestAuthentication{}, ErrInvalidArgument
	}
	return RequestAuthentication{credential: credential, proof: proof, method: method, targetURI: targetURI}, nil
}

func (RequestAuthentication) String() string               { return "RequestAuthentication{REDACTED}" }
func (RequestAuthentication) GoString() string             { return "RequestAuthentication{REDACTED}" }
func (RequestAuthentication) MarshalJSON() ([]byte, error) { return nil, ErrInvalidArgument }
func (value RequestAuthentication) Credential() string     { return value.credential }
func (value RequestAuthentication) Proof() string          { return value.proof }
func (value RequestAuthentication) Method() string         { return value.method }
func (value RequestAuthentication) TargetURI() string      { return value.targetURI }

type Identity struct {
	tenant    string
	principal string
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

func NewIdentity(tenant, principal string) (Identity, error) {
	if !identifierPattern.MatchString(tenant) || !identifierPattern.MatchString(principal) {
		return Identity{}, ErrInvalidArgument
	}
	return Identity{tenant: tenant, principal: principal}, nil
}

func (Identity) String() string               { return "Identity{REDACTED}" }
func (Identity) GoString() string             { return "Identity{REDACTED}" }
func (Identity) MarshalJSON() ([]byte, error) { return nil, ErrInvalidArgument }

type Authenticator interface {
	Authenticate(context.Context, RequestAuthentication) (Identity, error)
}

type ActionAuthorizer interface {
	AuthorizeAction(context.Context, Identity, Action) error
}

type ScopeAuthorizer interface {
	AuthorizeScope(context.Context, Identity, Action, coordination.Digest) error
}

type CapabilityOpener interface {
	OpenScope(context.Context, Identity, string) (coordination.Digest, error)
}

type ScopedOperation interface {
	Run(context.Context, Identity, Action, coordination.Digest) error
}

type Pipeline struct {
	authenticator Authenticator
	actions       ActionAuthorizer
	scopes        ScopeAuthorizer
}

func NewPipeline(authenticator Authenticator, actions ActionAuthorizer, scopes ScopeAuthorizer) (*Pipeline, error) {
	if authenticator == nil || actions == nil || scopes == nil {
		return nil, ErrInvalidArgument
	}
	return &Pipeline{authenticator: authenticator, actions: actions, scopes: scopes}, nil
}

func (pipeline *Pipeline) ExecutePublic(ctx context.Context, authentication RequestAuthentication, action Action, scope coordination.Digest, operation ScopedOperation) error {
	if !validAction(action) || !validDigest(scope) || operation == nil {
		return ErrInvalidArgument
	}
	identity, err := pipeline.admit(ctx, authentication, action)
	if err != nil {
		return err
	}
	if err := pipeline.scopes.AuthorizeScope(ctx, identity, action, scope); err != nil {
		return mapAuthorizationError(err)
	}
	return mapOperationError(operation.Run(ctx, identity, action, scope))
}

func (pipeline *Pipeline) ExecuteSealed(ctx context.Context, authentication RequestAuthentication, action Action, capability string, opener CapabilityOpener, operation ScopedOperation) error {
	if !validAction(action) || capability == "" || len(capability) > 4096 || opener == nil || operation == nil {
		return ErrInvalidArgument
	}
	identity, err := pipeline.admit(ctx, authentication, action)
	if err != nil {
		return err
	}
	scope, err := opener.OpenScope(ctx, identity, capability)
	if err != nil || !validDigest(scope) {
		if errors.Is(err, ErrInvalidCapability) {
			return ErrInvalidCapability
		}
		return ErrTemporarilyUnavailable
	}
	if err := pipeline.scopes.AuthorizeScope(ctx, identity, action, scope); err != nil {
		return mapAuthorizationError(err)
	}
	return mapOperationError(operation.Run(ctx, identity, action, scope))
}

func (pipeline *Pipeline) admit(ctx context.Context, authentication RequestAuthentication, action Action) (Identity, error) {
	identity, err := pipeline.authenticator.Authenticate(ctx, authentication)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return Identity{}, ErrUnauthenticated
		}
		return Identity{}, ErrTemporarilyUnavailable
	}
	if !identifierPattern.MatchString(identity.tenant) || !identifierPattern.MatchString(identity.principal) {
		return Identity{}, ErrTemporarilyUnavailable
	}
	if err := pipeline.actions.AuthorizeAction(ctx, identity, action); err != nil {
		return Identity{}, mapAuthorizationError(err)
	}
	return identity, nil
}

func mapAuthorizationError(err error) error {
	if errors.Is(err, ErrAccessDenied) {
		return ErrAccessDenied
	}
	return ErrTemporarilyUnavailable
}

func mapOperationError(err error) error {
	if err == nil || errors.Is(err, ErrInvalidCapability) {
		return err
	}
	return ErrTemporarilyUnavailable
}

func validDigest(value coordination.Digest) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
