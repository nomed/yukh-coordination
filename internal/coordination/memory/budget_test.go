package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

func TestCapabilityBudgetIsBoundedAndPrunesInForeground(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	budget, err := NewCapabilityBudget(1, time.Second, 7, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	principal := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	first, _ := coordination.NewCapabilityTokenID([16]byte{1})
	second, _ := coordination.NewCapabilityTokenID([16]byte{2})
	if err := budget.Reserve(context.Background(), principal, first, now.Add(30*time.Second), 7); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(context.Background(), principal, second, now.Add(30*time.Second), 7); !errors.Is(err, coordination.ErrUnavailable) {
		t.Fatalf("limit: %v", err)
	}
	if err := budget.Commit(context.Background(), principal, first, 7); err != nil {
		t.Fatal(err)
	}
	if err := budget.Replace(context.Background(), principal, first, second, now.Add(40*time.Second), 7); err != nil {
		t.Fatal(err)
	}
	if err := budget.Retire(context.Background(), principal, second, 7); err != nil {
		t.Fatal(err)
	}
	if err := budget.Reserve(context.Background(), principal, first, now.Add(30*time.Second), 7); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := budget.Reserve(context.Background(), principal, second, now.Add(30*time.Second), 7); err != nil {
		t.Fatalf("pending prune: %v", err)
	}
}

func TestCapabilityBudgetCancelAndTenantSeparation(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	budget, _ := NewCapabilityBudget(1, time.Second, 1, func() time.Time { return now })
	firstPrincipal := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	secondPrincipal := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	token, _ := coordination.NewCapabilityTokenID([16]byte{1})
	for _, principal := range []coordination.Digest{firstPrincipal, secondPrincipal} {
		if err := budget.Reserve(context.Background(), principal, token, now.Add(30*time.Second), 1); err != nil {
			t.Fatal(err)
		}
		if err := budget.Cancel(context.Background(), principal, token, 1); err != nil {
			t.Fatal(err)
		}
	}
	if token.String() != "CapabilityTokenID{REDACTED}" {
		t.Fatal("unsafe token formatting")
	}
}
