package jetstreamkv

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitives"
)

type integrationKeys struct {
	key  primitives.SealingKey
	next atomic.Uint32
}

func (keys *integrationKeys) Active(context.Context) (primitives.SealingKey, error) {
	return keys.key, nil
}
func (keys *integrationKeys) Open(context.Context, string) (primitives.SealingKey, error) {
	return keys.key, nil
}
func (keys *integrationKeys) NewTokenID() ([16]byte, error) {
	var value [16]byte
	value[0] = byte(keys.next.Add(1))
	return value, nil
}

func TestCapabilityBudgetAgainstDisposableNATS(t *testing.T) {
	connection := startServer(t, "14319")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	budget, err := OpenCapabilityBudget(ctx, connection, testConfig(1), 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	budget.now = func() time.Time { return now }
	principal := coordination.Digest("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	first, _ := coordination.NewCapabilityTokenID([16]byte{1})
	second, _ := coordination.NewCapabilityTokenID([16]byte{2})
	if err := budget.Reserve(ctx, principal, first, now.Add(30*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	if err := budget.Commit(ctx, principal, first, 1); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx, principal, second, now.Add(30*time.Second), 1); !errors.Is(err, coordination.ErrUnavailable) {
		t.Fatalf("limit: %v", err)
	}
	if err := budget.Replace(ctx, principal, first, second, now.Add(40*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	if err := budget.Retire(ctx, principal, second, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCapabilityBudget(ctx, connection, testConfig(1), 2, time.Second); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("changed limit accepted: %v", err)
	}
}

func TestCapabilityBudgetReconcilesOneExactAmbiguousMutation(t *testing.T) {
	connection := startServer(t, "14321")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	budget, err := OpenCapabilityBudget(ctx, connection, testConfig(1), 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	budget.now = func() time.Time { return now }
	hook := &hookedKV{KeyValue: budget.kv.(natsjs.KeyValue), loseCreate: true}
	budget.kv = hook
	principal := coordination.Digest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	token, _ := coordination.NewCapabilityTokenID([16]byte{1})
	if err := budget.Reserve(ctx, principal, token, now.Add(30*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	if hook.creates != 1 || hook.gets != 2 {
		t.Fatalf("reserve calls: create=%d get=%d", hook.creates, hook.gets)
	}
	hook.loseUpdate, hook.gets = true, 0
	if err := budget.Commit(ctx, principal, token, 1); err != nil {
		t.Fatal(err)
	}
	if hook.updates != 1 || hook.gets != 2 {
		t.Fatalf("commit calls: update=%d get=%d", hook.updates, hook.gets)
	}
}

func TestCapabilityBudgetConcurrentReserveNeverExceedsLimit(t *testing.T) {
	connection := startServer(t, "14320")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	budget, err := OpenCapabilityBudget(ctx, connection, testConfig(1), 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	budget.now = func() time.Time { return now }
	principal := coordination.Digest("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	var group sync.WaitGroup
	results := make(chan error, 10)
	for index := byte(1); index <= 10; index++ {
		group.Add(1)
		go func(value byte) {
			defer group.Done()
			token, _ := coordination.NewCapabilityTokenID([16]byte{value})
			results <- budget.Reserve(ctx, principal, token, now.Add(30*time.Second), 1)
		}(index)
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, coordination.ErrConflict) && !errors.Is(err, coordination.ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("successful reservations: %d", success)
	}
}

func TestCapabilityBudgetReplacesOlderEpochAndRejectsMalformedLedger(t *testing.T) {
	connection := startServer(t, "14322")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	budget, err := OpenCapabilityBudget(ctx, connection, testConfig(2), 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	budget.now = func() time.Time { return now }
	principal := coordination.Digest("abababababababababababababababababababababababababababababababab")
	token, _ := coordination.NewCapabilityTokenID([16]byte{1})
	old := `{"schema":1,"epoch":1,"entries":[{"token":"02000000000000000000000000000000","expires_at":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `","lease_expires_at":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `","phase":"active"}]}`
	if _, err := budget.kv.Create(ctx, string(principal), []byte(old)); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx, principal, token, now.Add(30*time.Second), 2); err != nil {
		t.Fatalf("replace old epoch: %v", err)
	}
	entry, err := budget.kv.Get(ctx, string(principal))
	if err != nil || !strings.Contains(string(entry.Value()), `"epoch":2`) || strings.Contains(string(entry.Value()), "020000") {
		t.Fatalf("replacement: %v %s", err, entry.Value())
	}

	malformedPrincipal := coordination.Digest("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	if _, err := budget.kv.Create(ctx, string(malformedPrincipal), []byte(`{"schema":1,"epoch":2,"entries":[{"token":"bad"}]}`)); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx, malformedPrincipal, token, now.Add(30*time.Second), 2); !errors.Is(err, coordination.ErrInvariant) {
		t.Fatalf("malformed ledger: %v", err)
	}

	futurePrincipal := coordination.Digest("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")
	if _, err := budget.kv.Create(ctx, string(futurePrincipal), []byte(`{"schema":1,"epoch":3,"entries":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(ctx, futurePrincipal, token, now.Add(30*time.Second), 2); !errors.Is(err, coordination.ErrInvariant) {
		t.Fatalf("epoch rollback: %v", err)
	}
}

func TestPrimitivesServiceLifecycleRestartConcurrencyAndFailureAgainstDisposableNATS(t *testing.T) {
	connection := startServer(t, "14323")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config := testConfig(1)
	store, err := Open(ctx, connection, config)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := OpenCapabilityBudget(ctx, connection, config, 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	budget.now = func() time.Time { return now }
	key, _ := primitives.NewSealingKey("integration-key", bytes.Repeat([]byte{1}, 32))
	keys := &integrationKeys{key: key}
	sealer, _ := primitives.NewAEADSealer(keys, bytes.NewReader(bytes.Repeat([]byte{2}, 8192)))
	newService := func() *primitives.Service {
		service, serviceErr := primitives.NewService(store, store, budget, sealer, keys, 1, time.Minute, func() time.Time { return now })
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	identity, _ := primitives.NewIdentity("tenant-a", "principal-a")
	scope := coordination.Digest(strings.Repeat("a", 64))
	holder := coordination.Digest(strings.Repeat("b", 64))
	acquired, err := newService().Acquire(ctx, identity, scope, holder, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	restarted := newService()
	if status, err := restarted.Inspect(ctx, identity, acquired.Capability); err != nil || status != coordination.LeaseValid {
		t.Fatalf("restart inspect: %s %v", status, err)
	}
	renewed, err := restarted.Renew(ctx, identity, acquired.Capability, now.Add(40*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Release(ctx, identity, renewed.Capability); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 2)
	for _, prefix := range []string{"c", "d"} {
		go func(prefix string) {
			_, acquireErr := restarted.Acquire(ctx, identity, coordination.Digest(strings.Repeat(prefix, 64)), holder, now.Add(30*time.Second))
			results <- acquireErr
		}(prefix)
	}
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, primitives.ErrUnavailable) && !errors.Is(err, primitives.ErrConflict) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("bounded concurrent acquisitions: %d", successes)
	}
	connection.Close()
	if _, err := restarted.Acquire(ctx, identity, coordination.Digest(strings.Repeat("e", 64)), holder, now.Add(30*time.Second)); !errors.Is(err, primitives.ErrUnavailable) {
		t.Fatalf("provider failure: %v", err)
	}
}
