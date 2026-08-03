// Package primitiveshttp composes the RFC-0017 authorization pipeline with
// the RFC-0015 application core. HTTP framing is deliberately separate.
package primitiveshttp

import (
	"context"
	"errors"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

type Bridge struct {
	pipeline *primitivesauth.Pipeline
	service  *primitives.Service
}

func NewBridge(pipeline *primitivesauth.Pipeline, service *primitives.Service) (*Bridge, error) {
	if pipeline == nil || service == nil {
		return nil, primitivesauth.ErrInvalidArgument
	}
	return &Bridge{pipeline: pipeline, service: service}, nil
}

func (bridge *Bridge) Consume(ctx context.Context, authentication primitivesauth.RequestAuthentication, scope, value coordination.Digest, expires time.Time) (coordination.NonceOutcome, error) {
	flow := &publicFlow{service: bridge.service, value: value, expires: expires}
	err := bridge.pipeline.ExecutePublic(ctx, authentication, primitivesauth.NonceConsume, scope, flow)
	return flow.nonce, err
}

func (bridge *Bridge) Acquire(ctx context.Context, authentication primitivesauth.RequestAuthentication, scope, holder coordination.Digest, expires time.Time) (primitives.LeaseResult, error) {
	flow := &publicFlow{service: bridge.service, holder: holder, expires: expires}
	err := bridge.pipeline.ExecutePublic(ctx, authentication, primitivesauth.LeaseAcquire, scope, flow)
	return flow.lease, err
}

func (bridge *Bridge) Inspect(ctx context.Context, authentication primitivesauth.RequestAuthentication, capability string) (coordination.LeaseStatus, error) {
	flow := &sealedFlow{service: bridge.service, capability: capability}
	err := bridge.pipeline.ExecuteSealed(ctx, authentication, primitivesauth.LeaseInspect, capability, flow, flow)
	return flow.status, err
}

func (bridge *Bridge) Renew(ctx context.Context, authentication primitivesauth.RequestAuthentication, capability string, expires time.Time) (primitives.LeaseResult, error) {
	flow := &sealedFlow{service: bridge.service, capability: capability, expires: expires}
	err := bridge.pipeline.ExecuteSealed(ctx, authentication, primitivesauth.LeaseRenew, capability, flow, flow)
	return flow.lease, err
}

func (bridge *Bridge) Release(ctx context.Context, authentication primitivesauth.RequestAuthentication, capability string) error {
	flow := &sealedFlow{service: bridge.service, capability: capability}
	return bridge.pipeline.ExecuteSealed(ctx, authentication, primitivesauth.LeaseRelease, capability, flow, flow)
}

type publicFlow struct {
	service       *primitives.Service
	value, holder coordination.Digest
	expires       time.Time
	nonce         coordination.NonceOutcome
	lease         primitives.LeaseResult
}

func (flow *publicFlow) Run(ctx context.Context, identity primitivesauth.Identity, action primitivesauth.Action, scope coordination.Digest) error {
	core, err := coreIdentity(identity)
	if err != nil {
		return err
	}
	switch action {
	case primitivesauth.NonceConsume:
		flow.nonce, err = flow.service.ConsumeNonce(ctx, core, scope, flow.value, flow.expires)
	case primitivesauth.LeaseAcquire:
		flow.lease, err = flow.service.Acquire(ctx, core, scope, flow.holder, flow.expires)
	default:
		return primitivesauth.ErrInvalidArgument
	}
	return mapCoreError(err)
}

type sealedFlow struct {
	service    *primitives.Service
	capability string
	expires    time.Time
	opened     primitives.OpenedCapability
	identity   primitives.Identity
	lease      primitives.LeaseResult
	status     coordination.LeaseStatus
}

func (flow *sealedFlow) OpenScope(ctx context.Context, identity primitivesauth.Identity, capability string) (coordination.Digest, error) {
	core, err := coreIdentity(identity)
	if err != nil {
		return "", primitivesauth.ErrTemporarilyUnavailable
	}
	opened, err := flow.service.OpenCapability(ctx, core, capability)
	if errors.Is(err, primitives.ErrConflict) || errors.Is(err, primitives.ErrInvalidArgument) {
		return "", primitivesauth.ErrInvalidCapability
	}
	if err != nil {
		return "", primitivesauth.ErrTemporarilyUnavailable
	}
	flow.identity, flow.opened = core, opened
	return opened.Scope(), nil
}

func (flow *sealedFlow) Run(ctx context.Context, _ primitivesauth.Identity, action primitivesauth.Action, scope coordination.Digest) error {
	if scope != flow.opened.Scope() {
		return primitivesauth.ErrInvalidCapability
	}
	var err error
	switch action {
	case primitivesauth.LeaseInspect:
		flow.status, err = flow.service.InspectOpened(ctx, flow.opened)
	case primitivesauth.LeaseRenew:
		flow.lease, err = flow.service.RenewOpened(ctx, flow.identity, flow.opened, flow.expires)
	case primitivesauth.LeaseRelease:
		err = flow.service.ReleaseOpened(ctx, flow.identity, flow.opened)
	default:
		return primitivesauth.ErrInvalidArgument
	}
	return mapCoreError(err)
}

func coreIdentity(identity primitivesauth.Identity) (primitives.Identity, error) {
	return primitives.NewIdentity(identity.Tenant(), identity.Principal())
}

func mapCoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, primitives.ErrConflict) || errors.Is(err, primitives.ErrInvalidArgument) {
		return primitivesauth.ErrInvalidCapability
	}
	if errors.Is(err, primitives.ErrInvariant) {
		return primitivesauth.ErrInvariantViolation
	}
	return primitivesauth.ErrTemporarilyUnavailable
}
