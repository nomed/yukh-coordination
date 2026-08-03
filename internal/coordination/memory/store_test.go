package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

func TestConformance(t *testing.T) {
	now := time.Now().UTC()
	store, err := New(time.Minute, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	key := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	firstDigest := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	secondDigest := coordination.Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	nonce := coordination.NonceValue{ValueDigest: firstDigest, ExpiresAt: now.Add(30 * time.Second), Epoch: 1}
	if outcome, err := store.Consume(context.Background(), key, nonce); err != nil || outcome != coordination.NonceConsumed {
		t.Fatalf("consume: %q, %v", outcome, err)
	}
	nonce.ValueDigest = secondDigest
	if outcome, err := store.Consume(context.Background(), key, nonce); err != nil || outcome != coordination.NonceReplayed {
		t.Fatalf("replay: %q, %v", outcome, err)
	}
	first, err := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: firstDigest, ExpiresAt: now.Add(20 * time.Second), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: secondDigest, ExpiresAt: now.Add(20 * time.Second), Epoch: 1}); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("contention: %v", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: secondDigest, ExpiresAt: now.Add(20 * time.Second), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if second.FencingToken() <= first.FencingToken() {
		t.Fatal("fencing token did not advance")
	}
}
