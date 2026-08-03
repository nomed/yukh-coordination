package jetstreamkv

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

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
