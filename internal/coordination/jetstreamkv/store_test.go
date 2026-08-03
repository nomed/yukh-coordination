package jetstreamkv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/coordination"
)

const (
	testKey    coordination.Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testValue  coordination.Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testHolder coordination.Digest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestNonceReplayAndFencedLease(t *testing.T) {
	connection := startServer(t, "14312")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, Retention: time.Hour, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	nonce := coordination.NonceValue{ValueDigest: testValue, ExpiresAt: now.Add(30 * time.Second), Epoch: 1}
	if outcome, err := store.Consume(ctx, testKey, nonce); err != nil || outcome != coordination.NonceConsumed {
		t.Fatalf("first nonce: %q, %v", outcome, err)
	}
	if outcome, err := store.Consume(ctx, testKey, nonce); err != nil || outcome != coordination.NonceReplayed {
		t.Fatalf("replayed nonce: %q, %v", outcome, err)
	}

	first, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testHolder, ExpiresAt: now.Add(30 * time.Second), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	firstToken := first.FencingToken()
	if firstToken == 0 {
		t.Fatal("zero fencing token")
	}
	if _, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testValue, ExpiresAt: now.Add(30 * time.Second), Epoch: 1}); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("competing lease: %v", err)
	}
	if err := first.Renew(ctx, now.Add(40*time.Second)); err != nil {
		t.Fatal(err)
	}
	if first.FencingToken() <= firstToken {
		t.Fatal("renew did not advance fencing token")
	}
	valid, err := first.Valid(ctx)
	if err != nil || !valid {
		t.Fatalf("renewed lease validity: %v, %v", valid, err)
	}
	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testValue, ExpiresAt: now.Add(30 * time.Second), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if second.FencingToken() <= first.FencingToken() {
		t.Fatal("reacquisition did not advance fencing token")
	}
	if valid, err := first.Valid(ctx); err != nil || valid {
		t.Fatalf("released lease validity: %v, %v", valid, err)
	}
}

func TestConcurrentNonceCreateHasOneConsumer(t *testing.T) {
	connection := startServer(t, "14315")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, Retention: time.Hour, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	nonce := coordination.NonceValue{ValueDigest: testValue, ExpiresAt: time.Now().UTC().Add(30 * time.Second), Epoch: 1}
	const contenders = 20
	outcomes := make(chan coordination.NonceOutcome, contenders)
	errorsSeen := make(chan error, contenders)
	var group sync.WaitGroup
	for range contenders {
		group.Add(1)
		go func() {
			defer group.Done()
			outcome, consumeErr := store.Consume(ctx, testKey, nonce)
			outcomes <- outcome
			errorsSeen <- consumeErr
		}()
	}
	group.Wait()
	close(outcomes)
	close(errorsSeen)
	for consumeErr := range errorsSeen {
		if consumeErr != nil {
			t.Fatal(consumeErr)
		}
	}
	consumed := 0
	for outcome := range outcomes {
		if outcome == coordination.NonceConsumed {
			consumed++
		}
	}
	if consumed != 1 {
		t.Fatalf("consumed outcomes: %d", consumed)
	}
	changed := nonce
	changed.ValueDigest = testHolder
	if outcome, err := store.Consume(ctx, testKey, changed); err != nil || outcome != coordination.NonceReplayed {
		t.Fatalf("changed replay: %q, %v", outcome, err)
	}
}

func TestExpiredLeaseCanBeReacquired(t *testing.T) {
	connection := startServer(t, "14313")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, Retention: time.Hour, Epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	store.now = func() time.Time { return base }
	first, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testHolder, ExpiresAt: base.Add(10 * time.Second), Epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(20 * time.Second) }
	second, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testValue, ExpiresAt: base.Add(40 * time.Second), Epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	if second.FencingToken() <= first.FencingToken() {
		t.Fatal("expired reacquisition did not advance fencing token")
	}
	if err := first.Renew(ctx, base.Add(50*time.Second)); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("stale owner renewed: %v", err)
	}
}

func TestOpenRejectsMismatchedBucket(t *testing.T) {
	connection := startServer(t, "14314")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config := Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, Retention: time.Hour, Epoch: 1}
	if _, err := Open(ctx, connection, config); err != nil {
		t.Fatal(err)
	}
	js, err := natsjs.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.Stream(ctx, "KV_"+NonceBucket)
	if err != nil {
		t.Fatal(err)
	}
	streamConfig := stream.CachedInfo().Config
	streamConfig.MaxMsgSize--
	if _, err := js.UpdateStream(ctx, streamConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, connection, config); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("mismatched bucket: %v", err)
	}
}

func TestOpenRejectsRestoredOldEpoch(t *testing.T) {
	connection := startServer(t, "14316")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config := Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, Retention: time.Hour, Epoch: 1}
	if _, err := Open(ctx, connection, config); err != nil {
		t.Fatal(err)
	}
	config.Epoch = 2
	if _, err := Open(ctx, connection, config); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("restored old epoch admitted: %v", err)
	}
}

func TestRejectsInvalidInputsWithoutSensitiveErrors(t *testing.T) {
	store := &Store{config: Config{MaxLifetime: time.Minute, Epoch: 1}, now: time.Now}
	_, err := store.Consume(context.Background(), coordination.Digest("private-value"), coordination.NonceValue{})
	if !errors.Is(err, coordination.ErrInvalidArgument) || strings.Contains(err.Error(), "private-value") {
		t.Fatalf("unsafe validation error: %v", err)
	}
}

func startServer(t *testing.T, port string) *nats.Conn {
	t.Helper()
	server := os.Getenv("YUKH_NATS_SERVER")
	if server == "" {
		t.Skip("YUKH_NATS_SERVER is not set")
	}
	command := exec.Command(server, "-js", "-p", port, "-sd", filepath.Join(t.TempDir(), "nats"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	var connection *nats.Conn
	var err error
	for range 50 {
		connection, err = nats.Connect("nats://127.0.0.1:"+port, nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}
