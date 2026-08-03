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

const (
	maxSafeInteger    = uint64(9_007_199_254_740_991)
	maxCapabilitySize = 3800
)

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
	budget coordination.CapabilityBudget
	epoch  uint64
	maxTTL time.Duration
	now    func() time.Time
}

func NewService(nonces coordination.NonceStore, leases coordination.FencedLeaseStore, budget coordination.CapabilityBudget, sealer CapabilitySealer, tokens TokenIDSource, epoch uint64, maxTTL time.Duration, now func() time.Time) (*Service, error) {
	if nonces == nil || leases == nil || budget == nil || sealer == nil || tokens == nil || epoch == 0 || epoch > maxSafeInteger || nonces.ConfiguredEpoch() != epoch || leases.ConfiguredEpoch() != epoch || budget.ConfiguredEpoch() != epoch || maxTTL <= 0 || now == nil {
		return nil, ErrInvalidArgument
	}
	return &Service{nonces: nonces, leases: leases, budget: budget, sealer: sealer, tokens: tokens, epoch: epoch, maxTTL: maxTTL, now: now}, nil
}

func (service *Service) Epoch() uint64 { return service.epoch }

func (service *Service) ConsumeNonce(ctx context.Context, identity Identity, scope, value coordination.Digest, expiresAt time.Time) (coordination.NonceOutcome, error) {
	key, err := deriveKey(identity, "nonce", scope)
	if err != nil || !validDigest(value) || !service.validExpiry(expiresAt) {
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

// OpenedCapability is authenticated capability state held only between the
// RFC-0017 action and scope authorization phases. It is never public output.
type OpenedCapability struct{ state CapabilityState }

func (OpenedCapability) String() string                    { return "OpenedCapability{REDACTED}" }
func (OpenedCapability) GoString() string                  { return "OpenedCapability{REDACTED}" }
func (OpenedCapability) MarshalJSON() ([]byte, error)      { return nil, ErrInvalidArgument }
func (opened OpenedCapability) Scope() coordination.Digest { return opened.state.key }

func (service *Service) OpenCapability(ctx context.Context, identity Identity, capability string) (OpenedCapability, error) {
	if capability == "" || len(capability) > maxCapabilitySize {
		return OpenedCapability{}, ErrInvalidArgument
	}
	state, err := service.sealer.Open(ctx, identity, capability)
	if errors.Is(err, ErrUnavailable) {
		return OpenedCapability{}, ErrUnavailable
	}
	if err != nil || state.epoch != service.epoch {
		return OpenedCapability{}, ErrConflict
	}
	return OpenedCapability{state: state}, nil
}

func (service *Service) Acquire(ctx context.Context, identity Identity, scope, holder coordination.Digest, expiresAt time.Time) (LeaseResult, error) {
	key, err := deriveKey(identity, "lease", scope)
	if err != nil || !validDigest(holder) || !service.validExpiry(expiresAt) {
		return LeaseResult{}, ErrInvalidArgument
	}
	token, budgetToken, principal, err := service.newBudgetToken(identity)
	if err != nil {
		return LeaseResult{}, err
	}
	if err := service.budget.Reserve(ctx, principal, budgetToken, expiresAt, service.epoch); err != nil {
		return LeaseResult{}, mapBudgetError(err)
	}
	held, err := service.leases.Acquire(ctx, key, coordination.LeaseValue{HolderDigest: holder, ExpiresAt: expiresAt, Epoch: service.epoch})
	if err != nil {
		if cancelErr := service.budget.Cancel(ctx, principal, budgetToken, service.epoch); cancelErr != nil {
			return LeaseResult{}, ErrUnavailable
		}
		return LeaseResult{}, mapStoreError(err)
	}
	result, err := service.sealLease(ctx, identity, key, holder, expiresAt, held.FencingToken(), token)
	if err != nil {
		if cancelErr := service.budget.Cancel(ctx, principal, budgetToken, service.epoch); cancelErr != nil {
			return LeaseResult{}, ErrUnavailable
		}
		return LeaseResult{}, err
	}
	if err := service.budget.Commit(ctx, principal, budgetToken, service.epoch); err != nil {
		return LeaseResult{}, mapBudgetError(err)
	}
	return result, nil
}

func (service *Service) Inspect(ctx context.Context, identity Identity, capability string) (coordination.LeaseStatus, error) {
	opened, err := service.OpenCapability(ctx, identity, capability)
	if err != nil {
		return "", err
	}
	return service.InspectOpened(ctx, opened)
}

func (service *Service) InspectOpened(ctx context.Context, opened OpenedCapability) (coordination.LeaseStatus, error) {
	state := opened.state
	value, err := coordination.NewLeaseResumeValue(state.holder, state.expiresAt, state.epoch, state.fencingToken)
	if err != nil {
		return "", ErrInvariant
	}
	status, err := service.leases.Inspect(ctx, state.key, value)
	return status, mapStoreError(err)
}

func (service *Service) Renew(ctx context.Context, identity Identity, capability string, expiresAt time.Time) (LeaseResult, error) {
	opened, err := service.OpenCapability(ctx, identity, capability)
	if err != nil {
		return LeaseResult{}, err
	}
	return service.RenewOpened(ctx, identity, opened, expiresAt)
}

func (service *Service) RenewOpened(ctx context.Context, identity Identity, opened OpenedCapability, expiresAt time.Time) (LeaseResult, error) {
	if !service.validExpiry(expiresAt) {
		return LeaseResult{}, ErrInvalidArgument
	}
	held, err := service.resumeOpened(ctx, opened)
	if err != nil {
		return LeaseResult{}, err
	}
	if err := held.Renew(ctx, expiresAt); err != nil {
		return LeaseResult{}, mapStoreError(err)
	}
	token, next, principal, err := service.newBudgetToken(identity)
	if err != nil {
		return LeaseResult{}, err
	}
	result, err := service.sealLease(ctx, identity, opened.state.key, opened.state.holder, expiresAt, held.FencingToken(), token)
	if err != nil {
		return LeaseResult{}, err
	}
	old, _ := coordination.NewCapabilityTokenID(opened.state.tokenID)
	if err := service.budget.Replace(ctx, principal, old, next, expiresAt, service.epoch); err != nil {
		return LeaseResult{}, mapBudgetError(err)
	}
	return result, nil
}

func (service *Service) validExpiry(expiresAt time.Time) bool {
	now := service.now().UTC()
	return expiresAt.Location() == time.UTC && expiresAt.Equal(expiresAt.Truncate(time.Millisecond)) && expiresAt.After(now) && !expiresAt.After(now.Add(service.maxTTL))
}

func (service *Service) Release(ctx context.Context, identity Identity, capability string) error {
	opened, err := service.OpenCapability(ctx, identity, capability)
	if err != nil {
		return err
	}
	return service.ReleaseOpened(ctx, identity, opened)
}

func (service *Service) ReleaseOpened(ctx context.Context, identity Identity, opened OpenedCapability) error {
	held, err := service.resumeOpened(ctx, opened)
	if err != nil {
		return err
	}
	if err := held.Release(ctx); err != nil {
		return mapStoreError(err)
	}
	principal, err := derivePrincipal(identity)
	if err != nil {
		return ErrInvariant
	}
	token, _ := coordination.NewCapabilityTokenID(opened.state.tokenID)
	return mapBudgetError(service.budget.Retire(ctx, principal, token, service.epoch))
}

func (service *Service) resumeOpened(ctx context.Context, opened OpenedCapability) (coordination.Lease, error) {
	state := opened.state
	value, err := coordination.NewLeaseResumeValue(state.holder, state.expiresAt, state.epoch, state.fencingToken)
	if err != nil {
		return nil, ErrInvariant
	}
	held, err := service.leases.Resume(ctx, state.key, value)
	if err != nil {
		return nil, mapStoreError(err)
	}
	return held, nil
}

func (service *Service) sealLease(ctx context.Context, identity Identity, key, holder coordination.Digest, expiresAt time.Time, fence uint64, tokenID [16]byte) (LeaseResult, error) {
	state, err := NewCapabilityState(key, holder, expiresAt, service.epoch, fence, tokenID)
	if err != nil {
		return LeaseResult{}, ErrInvariant
	}
	capability, err := service.sealer.Seal(ctx, identity, state)
	if err != nil {
		return LeaseResult{}, ErrUnavailable
	}
	if capability == "" || len(capability) > maxCapabilitySize {
		return LeaseResult{}, ErrInvariant
	}
	return LeaseResult{Capability: capability, FencingToken: fence, ExpiresAt: expiresAt}, nil
}

func (service *Service) newBudgetToken(identity Identity) ([16]byte, coordination.CapabilityTokenID, coordination.Digest, error) {
	raw, err := service.tokens.NewTokenID()
	if err != nil {
		return [16]byte{}, coordination.CapabilityTokenID{}, "", ErrUnavailable
	}
	token, err := coordination.NewCapabilityTokenID(raw)
	if err != nil {
		return [16]byte{}, coordination.CapabilityTokenID{}, "", ErrInvariant
	}
	principal, err := derivePrincipal(identity)
	if err != nil {
		return [16]byte{}, coordination.CapabilityTokenID{}, "", ErrInvalidArgument
	}
	return raw, token, principal, nil
}

func derivePrincipal(identity Identity) (coordination.Digest, error) {
	if !validIdentifier(identity.tenant) || !validIdentifier(identity.principal) {
		return "", ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte("yukh:coordination-capability-budget:v1\n" + identity.tenant + "\n" + identity.principal))
	return coordination.Digest(hexDigest(digest)), nil
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

func mapBudgetError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, coordination.ErrUnavailable), errors.Is(err, coordination.ErrConflict):
		return ErrUnavailable
	case errors.Is(err, coordination.ErrInvariant):
		return ErrInvariant
	default:
		return ErrInvariant
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
