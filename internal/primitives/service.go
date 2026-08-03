// Package primitives implements the RFC-0015 application boundary without
// adding routes to the coordination relay.
package primitives

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

var (
	ErrInvalidArgument = errors.New("primitives: invalid argument")
	ErrConflict        = errors.New("primitives: conflict")
	ErrUnavailable     = errors.New("primitives: temporarily unavailable")
	ErrInvariant       = errors.New("primitives: invariant violation")
)

const maxSafeInteger = uint64(9_007_199_254_740_991)

type Identity struct {
	tenant    string
	principal string
}

func NewIdentity(tenant, principal string) (Identity, error) {
	if !validIdentifier(tenant) || !validIdentifier(principal) {
		return Identity{}, ErrInvalidArgument
	}
	return Identity{tenant: tenant, principal: principal}, nil
}

func (Identity) String() string   { return "Identity{REDACTED}" }
func (Identity) GoString() string { return "Identity{REDACTED}" }

type CapabilityState struct {
	key          coordination.Digest
	holder       coordination.Digest
	expiresAt    time.Time
	epoch        uint64
	fencingToken uint64
	tokenID      [16]byte
}

func NewCapabilityState(key, holder coordination.Digest, expiresAt time.Time, epoch, fencingToken uint64, tokenID [16]byte) (CapabilityState, error) {
	resume, err := coordination.NewLeaseResumeValue(holder, expiresAt, epoch, fencingToken)
	if err != nil || !validDigest(key) || zeroTokenID(tokenID) {
		return CapabilityState{}, ErrInvalidArgument
	}
	return CapabilityState{key: key, holder: resume.HolderDigest(), expiresAt: resume.ExpiresAt(), epoch: resume.Epoch(), fencingToken: resume.FencingToken(), tokenID: tokenID}, nil
}

func (CapabilityState) String() string               { return "CapabilityState{REDACTED}" }
func (CapabilityState) GoString() string             { return "CapabilityState{REDACTED}" }
func (CapabilityState) MarshalJSON() ([]byte, error) { return nil, ErrInvalidArgument }

type CapabilitySealer interface {
	Seal(context.Context, Identity, CapabilityState) (string, error)
	Open(context.Context, Identity, string) (CapabilityState, error)
}

type TokenIDSource interface {
	NewTokenID() ([16]byte, error)
}

type Service struct {
	nonces coordination.NonceStore
	leases coordination.FencedLeaseStore
	sealer CapabilitySealer
	tokens TokenIDSource
	epoch  uint64
}

func NewService(nonces coordination.NonceStore, leases coordination.FencedLeaseStore, sealer CapabilitySealer, tokens TokenIDSource, epoch uint64) (*Service, error) {
	if nonces == nil || leases == nil || sealer == nil || tokens == nil || epoch == 0 || epoch > maxSafeInteger {
		return nil, ErrInvalidArgument
	}
	return &Service{nonces: nonces, leases: leases, sealer: sealer, tokens: tokens, epoch: epoch}, nil
}

func (service *Service) ConsumeNonce(ctx context.Context, identity Identity, scope, value coordination.Digest, expiresAt time.Time) (coordination.NonceOutcome, error) {
	key, err := deriveKey(identity, "nonce", scope)
	if err != nil || !validDigest(value) {
		return "", ErrInvalidArgument
	}
	outcome, err := service.nonces.Consume(ctx, key, coordination.NonceValue{ValueDigest: value, ExpiresAt: expiresAt, Epoch: service.epoch})
	return outcome, mapStoreError(err)
}

type LeaseResult struct {
	Capability   string
	FencingToken uint64
	ExpiresAt    time.Time
}

func (service *Service) Acquire(ctx context.Context, identity Identity, scope, holder coordination.Digest, expiresAt time.Time) (LeaseResult, error) {
	key, err := deriveKey(identity, "lease", scope)
	if err != nil || !validDigest(holder) {
		return LeaseResult{}, ErrInvalidArgument
	}
	held, err := service.leases.Acquire(ctx, key, coordination.LeaseValue{HolderDigest: holder, ExpiresAt: expiresAt, Epoch: service.epoch})
	if err != nil {
		return LeaseResult{}, mapStoreError(err)
	}
	return service.sealLease(ctx, identity, key, holder, expiresAt, held.FencingToken())
}

func (service *Service) Inspect(ctx context.Context, identity Identity, capability string) (bool, error) {
	_, held, err := service.resume(ctx, identity, capability)
	if err != nil {
		return false, err
	}
	valid, err := held.Valid(ctx)
	return valid, mapStoreError(err)
}

func (service *Service) Renew(ctx context.Context, identity Identity, capability string, expiresAt time.Time) (LeaseResult, error) {
	state, held, err := service.resume(ctx, identity, capability)
	if err != nil {
		return LeaseResult{}, err
	}
	if err := held.Renew(ctx, expiresAt); err != nil {
		return LeaseResult{}, mapStoreError(err)
	}
	return service.sealLease(ctx, identity, state.key, state.holder, expiresAt, held.FencingToken())
}

func (service *Service) Release(ctx context.Context, identity Identity, capability string) error {
	_, held, err := service.resume(ctx, identity, capability)
	if err != nil {
		return err
	}
	return mapStoreError(held.Release(ctx))
}

func (service *Service) resume(ctx context.Context, identity Identity, capability string) (CapabilityState, coordination.Lease, error) {
	if capability == "" || len(capability) > 4096 {
		return CapabilityState{}, nil, ErrInvalidArgument
	}
	state, err := service.sealer.Open(ctx, identity, capability)
	if errors.Is(err, ErrUnavailable) {
		return CapabilityState{}, nil, ErrUnavailable
	}
	if err != nil || state.epoch != service.epoch {
		return CapabilityState{}, nil, ErrConflict
	}
	value, err := coordination.NewLeaseResumeValue(state.holder, state.expiresAt, state.epoch, state.fencingToken)
	if err != nil {
		return CapabilityState{}, nil, ErrInvariant
	}
	held, err := service.leases.Resume(ctx, state.key, value)
	if err != nil {
		return CapabilityState{}, nil, mapStoreError(err)
	}
	return state, held, nil
}

func (service *Service) sealLease(ctx context.Context, identity Identity, key, holder coordination.Digest, expiresAt time.Time, fence uint64) (LeaseResult, error) {
	tokenID, err := service.tokens.NewTokenID()
	if err != nil {
		return LeaseResult{}, ErrUnavailable
	}
	state, err := NewCapabilityState(key, holder, expiresAt, service.epoch, fence, tokenID)
	if err != nil {
		return LeaseResult{}, ErrInvariant
	}
	capability, err := service.sealer.Seal(ctx, identity, state)
	if err != nil || capability == "" || len(capability) > 4096 {
		return LeaseResult{}, ErrUnavailable
	}
	return LeaseResult{Capability: capability, FencingToken: fence, ExpiresAt: expiresAt}, nil
}

func deriveKey(identity Identity, family string, scope coordination.Digest) (coordination.Digest, error) {
	if !validIdentifier(identity.tenant) || !validIdentifier(identity.principal) || !validDigest(scope) || (family != "nonce" && family != "lease") {
		return "", ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte("yukh:coordination-primitives:v1\n" + identity.tenant + "\n" + family + "\n" + string(scope)))
	return coordination.Digest(hexDigest(digest)), nil
}

func mapStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, coordination.ErrInvalidArgument):
		return ErrInvalidArgument
	case errors.Is(err, coordination.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
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

func validIdentifier(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-') {
			return false
		}
	}
	return true
}

func zeroTokenID(value [16]byte) bool {
	var all byte
	for _, item := range value {
		all |= item
	}
	return all == 0
}
func hexDigest(value [32]byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range value {
		out[i*2], out[i*2+1] = chars[b>>4], chars[b&15]
	}
	return string(out)
}
