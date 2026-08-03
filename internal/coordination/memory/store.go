// Package memory provides the RFC-0012 conformance adapter for tests only.
package memory

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type nonceRecord struct {
	value coordination.NonceValue
}

type leaseRecord struct {
	holder   coordination.Digest
	expires  time.Time
	epoch    uint64
	revision uint64
	released bool
}

type Store struct {
	mu          sync.Mutex
	MaxLifetime time.Duration
	Epoch       uint64
	Now         func() time.Time
	nonces      map[coordination.Digest]nonceRecord
	leases      map[coordination.Digest]leaseRecord
	revision    uint64
}

func New(maxLifetime time.Duration, epoch uint64, now func() time.Time) (*Store, error) {
	if maxLifetime <= 0 || epoch == 0 || now == nil {
		return nil, coordination.ErrInvalidArgument
	}
	return &Store{MaxLifetime: maxLifetime, Epoch: epoch, Now: now, nonces: make(map[coordination.Digest]nonceRecord), leases: make(map[coordination.Digest]leaseRecord)}, nil
}

func (store *Store) valid(key coordination.Digest, identity coordination.Digest, expires time.Time, epoch uint64) bool {
	now := store.Now().UTC()
	return digestPattern.MatchString(string(key)) && digestPattern.MatchString(string(identity)) && epoch == store.Epoch && expires.After(now) && !expires.After(now.Add(store.MaxLifetime))
}

func (store *Store) Consume(_ context.Context, key coordination.Digest, value coordination.NonceValue) (coordination.NonceOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.valid(key, value.ValueDigest, value.ExpiresAt, value.Epoch) {
		return "", coordination.ErrInvalidArgument
	}
	if _, exists := store.nonces[key]; exists {
		return coordination.NonceReplayed, nil
	}
	store.nonces[key] = nonceRecord{value: value}
	return coordination.NonceConsumed, nil
}

func (store *Store) Acquire(_ context.Context, key coordination.Digest, value coordination.LeaseValue) (coordination.Lease, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.valid(key, value.HolderDigest, value.ExpiresAt, value.Epoch) {
		return nil, coordination.ErrInvalidArgument
	}
	current, exists := store.leases[key]
	if exists && !current.released && current.expires.After(store.Now().UTC()) {
		return nil, coordination.ErrConflict
	}
	store.revision++
	current = leaseRecord{holder: value.HolderDigest, expires: value.ExpiresAt, epoch: value.Epoch, revision: store.revision}
	store.leases[key] = current
	return &lease{store: store, key: key, holder: value.HolderDigest, expires: value.ExpiresAt, revision: current.revision}, nil
}

type lease struct {
	store    *Store
	key      coordination.Digest
	holder   coordination.Digest
	expires  time.Time
	revision uint64
	released bool
}

func (held *lease) FencingToken() uint64 {
	held.store.mu.Lock()
	defer held.store.mu.Unlock()
	return held.revision
}

func (held *lease) Renew(_ context.Context, expires time.Time) error {
	held.store.mu.Lock()
	defer held.store.mu.Unlock()
	if held.released || !held.store.valid(held.key, held.holder, expires, held.store.Epoch) {
		return coordination.ErrConflict
	}
	current, exists := held.store.leases[held.key]
	if !exists || current.revision != held.revision {
		return coordination.ErrConflict
	}
	held.store.revision++
	held.revision, held.expires = held.store.revision, expires
	held.store.leases[held.key] = leaseRecord{holder: held.holder, expires: expires, epoch: held.store.Epoch, revision: held.revision}
	return nil
}

func (held *lease) Valid(_ context.Context) (bool, error) {
	held.store.mu.Lock()
	defer held.store.mu.Unlock()
	current, exists := held.store.leases[held.key]
	return exists && !held.released && current.revision == held.revision && current.expires.After(held.store.Now().UTC()), nil
}

func (held *lease) Release(_ context.Context) error {
	held.store.mu.Lock()
	defer held.store.mu.Unlock()
	current, exists := held.store.leases[held.key]
	if held.released || !exists || current.revision != held.revision {
		return coordination.ErrConflict
	}
	held.store.revision++
	held.revision, held.released = held.store.revision, true
	current.revision, current.released = held.revision, true
	held.store.leases[held.key] = current
	return nil
}
