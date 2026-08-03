package primitives

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/coordination/memory"
)

const (
	testScope  coordination.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHolder coordination.Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fixedKeys struct {
	active SealingKey
	old    map[string]SealingKey
	opens  int
}

func (keys *fixedKeys) Active(context.Context) (SealingKey, error) { return keys.active, nil }
func (keys *fixedKeys) Open(_ context.Context, id string) (SealingKey, error) {
	keys.opens++
	if id == keys.active.id {
		return keys.active, nil
	}
	if key, ok := keys.old[id]; ok {
		return key, nil
	}
	return SealingKey{}, ErrUnavailable
}

type tokenSource struct{ next byte }

func (source *tokenSource) NewTokenID() ([16]byte, error) {
	source.next++
	var value [16]byte
	for index := range value {
		value[index] = source.next
	}
	return value, nil
}

type countingBudget struct {
	coordination.CapabilityBudget
	reserve int
}

func (budget *countingBudget) Reserve(ctx context.Context, principal coordination.Digest, token coordination.CapabilityTokenID, expires time.Time, epoch uint64) error {
	budget.reserve++
	return budget.CapabilityBudget.Reserve(ctx, principal, token, expires, epoch)
}

type countingLeaseStore struct {
	coordination.FencedLeaseStore
	resume int
}

func (store *countingLeaseStore) Resume(ctx context.Context, key coordination.Digest, value coordination.LeaseResumeValue) (coordination.Lease, error) {
	store.resume++
	return store.FencedLeaseStore.Resume(ctx, key, value)
}

func testService(t *testing.T, now *time.Time, keys *fixedKeys) (*Service, Identity) {
	t.Helper()
	store, err := memory.New(time.Minute, 1, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := NewAEADSealer(keys, bytes.NewReader(bytes.Repeat([]byte{7}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	budget, err := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, store, budget, sealer, &tokenSource{}, 1, time.Minute, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewIdentity("tenant-a", "principal-a")
	if err != nil {
		t.Fatal(err)
	}
	return service, identity
}

func TestLeaseLifecycleSurvivesServiceRestart(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	key, _ := NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	keys := &fixedKeys{active: key, old: map[string]SealingKey{}}
	service, identity := testService(t, &now, keys)
	expires := now.Add(30 * time.Second)
	result, err := service.Acquire(context.Background(), identity, testScope, testHolder, expires)
	if err != nil {
		t.Fatal(err)
	}
	if result.Capability == "" || result.FencingToken == 0 {
		t.Fatal("incomplete acquisition")
	}
	if status, err := service.Inspect(context.Background(), identity, result.Capability); err != nil || status != coordination.LeaseValid {
		t.Fatalf("inspect: %v %v", status, err)
	}
	if keys.opens != 1 {
		t.Fatalf("capability opens: %d", keys.opens)
	}
	opened, err := service.OpenCapability(context.Background(), identity, result.Capability)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := service.InspectOpened(context.Background(), opened); err != nil || status != coordination.LeaseValid {
		t.Fatalf("opened inspect: %v %v", status, err)
	}
	if keys.opens != 2 {
		t.Fatalf("opened capability was reopened: %d", keys.opens)
	}

	// A new Service has no process-local lease registry and resumes only from
	// the sealed capability plus the authoritative store.
	restarted := *service
	renewed, err := restarted.Renew(context.Background(), identity, result.Capability, now.Add(40*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.FencingToken <= result.FencingToken {
		t.Fatal("fence did not advance")
	}
	if status, err := service.Inspect(context.Background(), identity, result.Capability); err != nil || status != coordination.LeaseStale {
		t.Fatalf("old capability: %s %v", status, err)
	}
	if err := restarted.Release(context.Background(), identity, renewed.Capability); err != nil {
		t.Fatal(err)
	}
	if status, err := restarted.Inspect(context.Background(), identity, renewed.Capability); err != nil || status != coordination.LeaseReleased {
		t.Fatalf("released capability: %s %v", status, err)
	}
}

func TestCapabilityBindsIdentityAndSupportsBoundedRotation(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	oldKey, _ := NewSealingKey("old-key", bytes.Repeat([]byte{2}, 32))
	newKey, _ := NewSealingKey("new-key", bytes.Repeat([]byte{3}, 32))
	keys := &fixedKeys{active: oldKey, old: map[string]SealingKey{}}
	service, identity := testService(t, &now, keys)
	result, err := service.Acquire(context.Background(), identity, testScope, testHolder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewIdentity("tenant-b", "principal-a")
	if _, err := service.Inspect(context.Background(), other, result.Capability); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-tenant capability: %v", err)
	}
	keys.old[oldKey.id], keys.active = oldKey, newKey
	if status, err := service.Inspect(context.Background(), identity, result.Capability); err != nil || status != coordination.LeaseValid {
		t.Fatalf("decrypt-only rotation: %v %v", status, err)
	}
	delete(keys.old, oldKey.id)
	if _, err := service.Inspect(context.Background(), identity, result.Capability); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost key: %v", err)
	}
}

func TestCapabilityFromEarlierEpochFailsBeforeCoordinationLookup(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	key, _ := NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	keys := &fixedKeys{active: key, old: map[string]SealingKey{}}
	sealer, _ := NewAEADSealer(keys, bytes.NewReader(bytes.Repeat([]byte{7}, 512)))
	first, _ := NewService(store, store, budget, sealer, &tokenSource{}, 1, time.Minute, func() time.Time { return now })
	identity, _ := NewIdentity("tenant-a", "principal-a")
	acquired, err := first.Acquire(context.Background(), identity, testScope, testHolder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(store, store, budget, sealer, &tokenSource{}, 2, time.Minute, func() time.Time { return now }); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("mismatched adapter epochs: %v", err)
	}
	secondStore, _ := memory.New(time.Minute, 2, func() time.Time { return now })
	secondBudget, _ := memory.NewCapabilityBudget(32, time.Second, 2, func() time.Time { return now })
	second, err := NewService(secondStore, secondStore, secondBudget, sealer, &tokenSource{}, 2, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Inspect(context.Background(), identity, acquired.Capability); !errors.Is(err, ErrConflict) {
		t.Fatalf("earlier epoch capability: %v", err)
	}
}

func TestNonceKeysAreTenantAndFamilySeparated(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	key, _ := NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	service, identity := testService(t, &now, &fixedKeys{active: key, old: map[string]SealingKey{}})
	if outcome, err := service.ConsumeNonce(context.Background(), identity, testScope, testHolder, now.Add(20*time.Second)); err != nil || outcome != coordination.NonceConsumed {
		t.Fatalf("consume: %s %v", outcome, err)
	}
	if outcome, err := service.ConsumeNonce(context.Background(), identity, testScope, testHolder, now.Add(20*time.Second)); err != nil || outcome != coordination.NonceReplayed {
		t.Fatalf("replay: %s %v", outcome, err)
	}
	other, _ := NewIdentity("tenant-b", "principal-a")
	if outcome, err := service.ConsumeNonce(context.Background(), other, testScope, testHolder, now.Add(20*time.Second)); err != nil || outcome != coordination.NonceConsumed {
		t.Fatalf("tenant separation: %s %v", outcome, err)
	}
}

func TestSensitiveValuesAreNotSerializable(t *testing.T) {
	state, err := NewCapabilityState(testScope, testHolder, time.Date(2026, 8, 3, 12, 0, 30, 0, time.UTC), 1, 2, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(state); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("serialized state: %v", err)
	}
	if state.String() != "CapabilityState{REDACTED}" {
		t.Fatal("unsafe state formatting")
	}
}

func TestServiceEnforcesPerPrincipalCapabilityLimit(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	budget, _ := memory.NewCapabilityBudget(1, time.Second, 1, func() time.Time { return now })
	key, _ := NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	keys := &fixedKeys{active: key, old: map[string]SealingKey{}}
	sealer, _ := NewAEADSealer(keys, bytes.NewReader(bytes.Repeat([]byte{7}, 512)))
	service, _ := NewService(store, store, budget, sealer, &tokenSource{}, 1, time.Minute, func() time.Time { return now })
	identity, _ := NewIdentity("tenant-a", "principal-a")
	first, err := service.Acquire(context.Background(), identity, testScope, testHolder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	otherScope := coordination.Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	if _, err := service.Acquire(context.Background(), identity, otherScope, testHolder, now.Add(30*time.Second)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("budget exhaustion: %v", err)
	}
	if err := service.Release(context.Background(), identity, first.Capability); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Acquire(context.Background(), identity, otherScope, testHolder, now.Add(30*time.Second)); err != nil {
		t.Fatalf("budget not retired: %v", err)
	}
}

func TestExpiryPolicyRejectsBeforeBudgetOrResumeProviderCalls(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	baseStore, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	baseBudget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	store := &countingLeaseStore{FencedLeaseStore: baseStore}
	budget := &countingBudget{CapabilityBudget: baseBudget}
	key, _ := NewSealingKey("key-a", bytes.Repeat([]byte{1}, 32))
	keys := &fixedKeys{active: key, old: map[string]SealingKey{}}
	sealer, _ := NewAEADSealer(keys, bytes.NewReader(bytes.Repeat([]byte{7}, 512)))
	service, _ := NewService(baseStore, store, budget, sealer, &tokenSource{}, 1, time.Minute, func() time.Time { return now })
	identity, _ := NewIdentity("tenant-a", "principal-a")
	if _, err := service.Acquire(context.Background(), identity, testScope, testHolder, now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("overlong acquire: %v", err)
	}
	if budget.reserve != 0 {
		t.Fatalf("invalid acquire reached budget: %d", budget.reserve)
	}
	acquired, err := service.Acquire(context.Background(), identity, testScope, testHolder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	before := store.resume
	if _, err := service.Renew(context.Background(), identity, acquired.Capability, now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("overlong renew: %v", err)
	}
	if store.resume != before {
		t.Fatalf("invalid renew reached resume: before=%d after=%d", before, store.resume)
	}
}
