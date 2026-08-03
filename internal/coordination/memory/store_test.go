package memory

import (
	"context"
	"encoding/json"
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

func TestResumeReconstructsExactLeaseAndRejectsStaleState(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := New(time.Minute, 7, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	key := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	holder := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	expires := now.Add(30 * time.Second)
	acquired, err := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: holder, ExpiresAt: expires, Epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	resume := mustResumeValue(t, holder, expires, 7, acquired.FencingToken())
	reconstructed, err := store.Resume(context.Background(), key, resume)
	if err != nil {
		t.Fatal(err)
	}
	if valid, validErr := reconstructed.Valid(context.Background()); validErr != nil || !valid {
		t.Fatalf("resumed validity: %v, %v", valid, validErr)
	}
	if err := reconstructed.Renew(context.Background(), now.Add(40*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resume(context.Background(), key, resume); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("old fence resumed after renew: %v", err)
	}
	resume = mustResumeValue(t, holder, now.Add(40*time.Second), 7, reconstructed.FencingToken())
	reconstructed, err = store.Resume(context.Background(), key, resume)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconstructed.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	resume = mustResumeValue(t, holder, now.Add(40*time.Second), 7, reconstructed.FencingToken())
	if _, err := store.Resume(context.Background(), key, resume); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("released lease resumed: %v", err)
	}
}

func TestResumeRejectsInvalidAndExpiredState(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, err := New(time.Minute, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	key := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	holder := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	expires := now.Add(20 * time.Second)
	held, err := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: holder, ExpiresAt: expires, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	valid := mustResumeValue(t, holder, expires, 1, held.FencingToken())
	if _, err := store.Resume(context.Background(), key, coordination.LeaseResumeValue{}); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("zero resume: %v", err)
	}
	if _, err := coordination.NewLeaseResumeValue(holder, expires.Add(time.Nanosecond), 1, held.FencingToken()); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("non-millisecond expiry: %v", err)
	}
	changed := mustResumeValue(t, coordination.Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), expires, 1, held.FencingToken())
	if _, err := store.Resume(context.Background(), key, changed); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("changed holder: %v", err)
	}
	store.Now = func() time.Time { return expires }
	if _, err := store.Resume(context.Background(), key, valid); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("expired resume: %v", err)
	}
	if got := valid.String(); got != "LeaseResumeValue{REDACTED}" {
		t.Fatalf("unsafe formatting: %q", got)
	}
	if _, err := json.Marshal(valid); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("resume value serialized: %v", err)
	}
}

func TestInspectClassifiesTerminalState(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store, _ := New(time.Minute, 1, func() time.Time { return now })
	key := coordination.Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	holder := coordination.Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	expires := now.Add(20 * time.Second)
	held, _ := store.Acquire(context.Background(), key, coordination.LeaseValue{HolderDigest: holder, ExpiresAt: expires, Epoch: 1})
	resume := mustResumeValue(t, holder, expires, 1, held.FencingToken())
	if status, err := store.Inspect(context.Background(), key, resume); err != nil || status != coordination.LeaseValid {
		t.Fatalf("valid: %s %v", status, err)
	}
	store.Now = func() time.Time { return expires }
	if status, err := store.Inspect(context.Background(), key, resume); err != nil || status != coordination.LeaseExpired {
		t.Fatalf("expired: %s %v", status, err)
	}
	store.Now = func() time.Time { return now }
	if err := held.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, err := store.Inspect(context.Background(), key, resume); err != nil || status != coordination.LeaseReleased {
		t.Fatalf("released: %s %v", status, err)
	}
	changed := mustResumeValue(t, holder, expires, 1, resume.FencingToken()+2)
	if status, err := store.Inspect(context.Background(), key, changed); err != nil || status != coordination.LeaseStale {
		t.Fatalf("stale: %s %v", status, err)
	}
}

func mustResumeValue(t *testing.T, holder coordination.Digest, expires time.Time, epoch, token uint64) coordination.LeaseResumeValue {
	t.Helper()
	value, err := coordination.NewLeaseResumeValue(holder, expires, epoch, token)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
