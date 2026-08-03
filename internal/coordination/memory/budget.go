package memory

import (
	"context"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

type budgetEntry struct {
	token        coordination.CapabilityTokenID
	expires      time.Time
	leaseExpires time.Time
	active       bool
}

type CapabilityBudget struct {
	mu         sync.Mutex
	limit      int
	pendingTTL time.Duration
	epoch      uint64
	now        func() time.Time
	entries    map[coordination.Digest][]budgetEntry
}

func NewCapabilityBudget(limit int, pendingTTL time.Duration, epoch uint64, now func() time.Time) (*CapabilityBudget, error) {
	if limit < 1 || limit > 32 || pendingTTL <= 0 || pendingTTL > 5*time.Second || epoch == 0 || now == nil {
		return nil, coordination.ErrInvalidArgument
	}
	return &CapabilityBudget{limit: limit, pendingTTL: pendingTTL, epoch: epoch, now: now, entries: make(map[coordination.Digest][]budgetEntry)}, nil
}

func (budget *CapabilityBudget) Reserve(_ context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, expires time.Time, epoch uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if !digestPattern.MatchString(string(principal)) || epoch != budget.epoch || expires.Location() != time.UTC || !expires.Equal(expires.Truncate(time.Millisecond)) || !expires.After(budget.now().UTC()) {
		return coordination.ErrInvalidArgument
	}
	entries := budget.prune(principal)
	for _, entry := range entries {
		if entry.token == token {
			return coordination.ErrConflict
		}
	}
	if len(entries) >= budget.limit {
		return coordination.ErrUnavailable
	}
	pending := budget.now().UTC().Add(budget.pendingTTL)
	if expires.Before(pending) {
		pending = expires
	}
	budget.entries[principal] = append(entries, budgetEntry{token: token, expires: pending, leaseExpires: expires})
	return nil
}

func (budget *CapabilityBudget) Commit(_ context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	entries, index, err := budget.find(principal, token, epoch)
	if err != nil {
		return err
	}
	if entries[index].active {
		return coordination.ErrConflict
	}
	entries[index].active = true
	entries[index].expires = entries[index].leaseExpires
	budget.entries[principal] = entries
	return nil
}

func (budget *CapabilityBudget) Cancel(_ context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	entries, index, err := budget.find(principal, token, epoch)
	if err != nil {
		return err
	}
	if entries[index].active {
		return coordination.ErrConflict
	}
	budget.remove(principal, entries, index)
	return nil
}

func (budget *CapabilityBudget) Replace(_ context.Context, principal coordination.Digest, old, next coordination.CapabilityTokenID, expires time.Time, epoch uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	entries, index, err := budget.find(principal, old, epoch)
	if err != nil || !entries[index].active {
		if err != nil {
			return err
		}
		return coordination.ErrConflict
	}
	for _, entry := range entries {
		if entry.token == next {
			return coordination.ErrConflict
		}
	}
	if !expires.After(budget.now().UTC()) || expires.Location() != time.UTC || !expires.Equal(expires.Truncate(time.Millisecond)) {
		return coordination.ErrInvalidArgument
	}
	entries[index] = budgetEntry{token: next, expires: expires, leaseExpires: expires, active: true}
	budget.entries[principal] = entries
	return nil
}

func (budget *CapabilityBudget) Retire(_ context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	entries, index, err := budget.find(principal, token, epoch)
	if err != nil || !entries[index].active {
		if err != nil {
			return err
		}
		return coordination.ErrConflict
	}
	budget.remove(principal, entries, index)
	return nil
}

func (budget *CapabilityBudget) prune(principal coordination.Digest) []budgetEntry {
	now := budget.now().UTC()
	source := budget.entries[principal]
	kept := source[:0]
	for _, entry := range source {
		if entry.expires.After(now) {
			kept = append(kept, entry)
		}
	}
	budget.entries[principal] = kept
	return kept
}

func (budget *CapabilityBudget) find(principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) ([]budgetEntry, int, error) {
	if !digestPattern.MatchString(string(principal)) || epoch != budget.epoch {
		return nil, 0, coordination.ErrInvalidArgument
	}
	entries := budget.prune(principal)
	for index, entry := range entries {
		if entry.token == token {
			return entries, index, nil
		}
	}
	return nil, 0, coordination.ErrConflict
}

func (budget *CapabilityBudget) remove(principal coordination.Digest, entries []budgetEntry, index int) {
	copy(entries[index:], entries[index+1:])
	budget.entries[principal] = entries[:len(entries)-1]
}
