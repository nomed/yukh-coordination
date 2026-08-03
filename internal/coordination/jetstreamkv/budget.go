package jetstreamkv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/coordination"
)

const (
	CapabilityBudgetBucket = "YUKH_COORDINATION_CAPABILITY_BUDGET_V1"
	maxBudgetValueBytes    = int32(8192)
)

type budgetSlot struct {
	Token        string `json:"token"`
	ExpiresAt    string `json:"expires_at"`
	LeaseExpires string `json:"lease_expires_at"`
	Phase        string `json:"phase"`
}

type budgetValue struct {
	Schema  int          `json:"schema"`
	Epoch   uint64       `json:"epoch"`
	Entries []budgetSlot `json:"entries"`
}

type CapabilityBudget struct {
	kv         atomicKV
	limit      int
	pendingTTL time.Duration
	epoch      uint64
	now        func() time.Time
}

func OpenCapabilityBudget(ctx context.Context, connection *nats.Conn, config Config, limit int, pendingTTL time.Duration) (*CapabilityBudget, error) {
	if connection == nil || limit < 1 || limit > 32 || pendingTTL <= 0 || pendingTTL > 5*time.Second || config.Replicas < 1 || config.Replicas > 5 || config.Retention <= config.MaxLifetime || config.Epoch == 0 {
		return nil, coordination.ErrInvalidArgument
	}
	js, err := natsjs.New(connection)
	if err != nil {
		return nil, coordination.ErrUnavailable
	}
	expectedConfig := expected(CapabilityBudgetBucket, "Yukh bounded capability accounting", config)
	expectedConfig.MaxValueSize = maxBudgetValueBytes
	kv, err := js.KeyValue(ctx, CapabilityBudgetBucket)
	if errors.Is(err, natsjs.ErrBucketNotFound) && config.Bootstrap {
		kv, err = js.CreateKeyValue(ctx, expectedConfig)
	}
	if err != nil {
		return nil, coordination.ErrUnavailable
	}
	status, err := kv.Status(ctx)
	if err != nil || !matchingStatus(status, expectedConfig) {
		return nil, coordination.ErrInvalidArgument
	}
	return &CapabilityBudget{kv: kv, limit: limit, pendingTTL: pendingTTL, epoch: config.Epoch, now: time.Now}, nil
}

func (budget *CapabilityBudget) Reserve(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, expires time.Time, epoch uint64) error {
	if err := budget.validate(principal, expires, epoch); err != nil {
		return err
	}
	return budget.mutate(ctx, principal, func(value *budgetValue) error {
		budget.prune(value)
		encoded := tokenText(token)
		if findSlot(value.Entries, encoded) >= 0 {
			return coordination.ErrConflict
		}
		if len(value.Entries) >= budget.limit {
			return coordination.ErrUnavailable
		}
		pending := budget.now().UTC().Add(budget.pendingTTL)
		if expires.Before(pending) {
			pending = expires
		}
		value.Entries = append(value.Entries, budgetSlot{Token: encoded, ExpiresAt: formatTime(pending), LeaseExpires: formatTime(expires), Phase: "pending"})
		return nil
	})
}

func (budget *CapabilityBudget) Commit(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	return budget.change(ctx, principal, token, epoch, func(value *budgetValue, index int) error {
		if value.Entries[index].Phase != "pending" {
			return coordination.ErrConflict
		}
		value.Entries[index].Phase = "active"
		value.Entries[index].ExpiresAt = value.Entries[index].LeaseExpires
		return nil
	})
}

func (budget *CapabilityBudget) Cancel(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	return budget.change(ctx, principal, token, epoch, func(value *budgetValue, index int) error {
		if value.Entries[index].Phase != "pending" {
			return coordination.ErrConflict
		}
		value.Entries = append(value.Entries[:index], value.Entries[index+1:]...)
		return nil
	})
}

func (budget *CapabilityBudget) Replace(ctx context.Context, principal coordination.Digest, old, next coordination.CapabilityTokenID, expires time.Time, epoch uint64) error {
	if err := budget.validate(principal, expires, epoch); err != nil {
		return err
	}
	return budget.change(ctx, principal, old, epoch, func(value *budgetValue, index int) error {
		if value.Entries[index].Phase != "active" || findSlot(value.Entries, tokenText(next)) >= 0 {
			return coordination.ErrConflict
		}
		value.Entries[index] = budgetSlot{Token: tokenText(next), ExpiresAt: formatTime(expires), LeaseExpires: formatTime(expires), Phase: "active"}
		return nil
	})
}

func (budget *CapabilityBudget) Retire(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64) error {
	return budget.change(ctx, principal, token, epoch, func(value *budgetValue, index int) error {
		if value.Entries[index].Phase != "active" {
			return coordination.ErrConflict
		}
		value.Entries = append(value.Entries[:index], value.Entries[index+1:]...)
		return nil
	})
}

func (budget *CapabilityBudget) change(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, epoch uint64, change func(*budgetValue, int) error) error {
	if !validDigest(principal) || epoch != budget.epoch {
		return coordination.ErrInvalidArgument
	}
	return budget.mutate(ctx, principal, func(value *budgetValue) error {
		budget.prune(value)
		index := findSlot(value.Entries, tokenText(token))
		if index < 0 {
			return coordination.ErrConflict
		}
		return change(value, index)
	})
}

func (budget *CapabilityBudget) mutate(ctx context.Context, principal coordination.Digest, change func(*budgetValue) error) error {
	entry, err := budget.kv.Get(ctx, string(principal))
	value := budgetValue{Schema: 1, Epoch: budget.epoch, Entries: []budgetSlot{}}
	var revision uint64
	missing := errors.Is(err, natsjs.ErrKeyNotFound) || errors.Is(err, natsjs.ErrKeyDeleted)
	if err != nil && !missing {
		return coordination.ErrUnavailable
	}
	if !missing {
		revision = entry.Revision()
		if err := decodeBudget(entry.Value(), &value, budget.epoch); err != nil {
			return err
		}
	}
	if err := change(&value); err != nil {
		return err
	}
	sort.Slice(value.Entries, func(i, j int) bool { return value.Entries[i].Token < value.Entries[j].Token })
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > int(maxBudgetValueBytes) {
		return coordination.ErrUnavailable
	}
	var mutationErr error
	if missing {
		_, mutationErr = budget.kv.Create(ctx, string(principal), raw)
	} else {
		_, mutationErr = budget.kv.Update(ctx, string(principal), raw, revision)
	}
	if mutationErr == nil {
		return nil
	}
	reconciled, getErr := budget.kv.Get(ctx, string(principal))
	if getErr != nil {
		return coordination.ErrUnavailable
	}
	if reconciled.Revision() > revision && string(reconciled.Value()) == string(raw) {
		return nil
	}
	return coordination.ErrConflict
}

func (budget *CapabilityBudget) validate(principal coordination.Digest, expires time.Time, epoch uint64) error {
	if !validDigest(principal) || epoch != budget.epoch || expires.Location() != time.UTC || !expires.Equal(expires.Truncate(time.Millisecond)) || !expires.After(budget.now().UTC()) {
		return coordination.ErrInvalidArgument
	}
	return nil
}

func (budget *CapabilityBudget) prune(value *budgetValue) {
	now := budget.now().UTC()
	kept := value.Entries[:0]
	for _, entry := range value.Entries {
		expires, err := time.Parse(time.RFC3339Nano, entry.ExpiresAt)
		if err == nil && expires.After(now) {
			kept = append(kept, entry)
		}
	}
	value.Entries = kept
}

func decodeBudget(raw []byte, value *budgetValue, epoch uint64) error {
	if len(raw) == 0 || len(raw) > int(maxBudgetValueBytes) || json.Unmarshal(raw, value) != nil || value.Schema != 1 || value.Epoch != epoch || len(value.Entries) > 32 {
		return coordination.ErrUnavailable
	}
	for _, entry := range value.Entries {
		if len(entry.Token) != 32 || (entry.Phase != "pending" && entry.Phase != "active") {
			return coordination.ErrUnavailable
		}
		if _, err := hex.DecodeString(entry.Token); err != nil {
			return coordination.ErrUnavailable
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.ExpiresAt); err != nil {
			return coordination.ErrUnavailable
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.LeaseExpires); err != nil {
			return coordination.ErrUnavailable
		}
	}
	return nil
}

func tokenText(token coordination.CapabilityTokenID) string { return hex.EncodeToString(token[:]) }
func findSlot(entries []budgetSlot, token string) int {
	for index, entry := range entries {
		if entry.Token == token {
			return index
		}
	}
	return -1
}
func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
