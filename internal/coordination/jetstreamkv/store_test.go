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
	store, err := Open(ctx, connection, testConfig(1))
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
	store, err := Open(ctx, connection, testConfig(1))
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
	store, err := Open(ctx, connection, testConfig(7))
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
	hook := &hookedKV{KeyValue: store.leases.(natsjs.KeyValue), loseUpdate: true}
	store.leases = hook
	second, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testValue, ExpiresAt: base.Add(40 * time.Second), Epoch: 7})
	if err != nil {
		t.Fatal(err)
	}
	if second.FencingToken() <= first.FencingToken() {
		t.Fatal("expired reacquisition did not advance fencing token")
	}
	if hook.updates != 1 || hook.gets != 2 {
		t.Fatalf("takeover calls: update=%d get=%d", hook.updates, hook.gets)
	}
	if err := first.Renew(ctx, base.Add(50*time.Second)); !errors.Is(err, coordination.ErrConflict) {
		t.Fatalf("stale owner renewed: %v", err)
	}
}

type hookedKV struct {
	natsjs.KeyValue
	loseCreate bool
	loseUpdate bool
	creates    int
	updates    int
	gets       int
}

type failingKV struct {
	creates int
	updates int
	gets    int
}

func (failure *failingKV) Create(context.Context, string, []byte, ...natsjs.KVCreateOpt) (uint64, error) {
	failure.creates++
	return 0, context.DeadlineExceeded
}

func (failure *failingKV) Update(context.Context, string, []byte, uint64) (uint64, error) {
	failure.updates++
	return 0, context.DeadlineExceeded
}

func (failure *failingKV) Get(context.Context, string) (natsjs.KeyValueEntry, error) {
	failure.gets++
	return nil, context.DeadlineExceeded
}

func (hook *hookedKV) Create(ctx context.Context, key string, value []byte, options ...natsjs.KVCreateOpt) (uint64, error) {
	hook.creates++
	revision, err := hook.KeyValue.Create(ctx, key, value, options...)
	if err == nil && hook.loseCreate {
		hook.loseCreate = false
		return 0, errors.New("simulated lost acknowledgement")
	}
	return revision, err
}

func (hook *hookedKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	hook.updates++
	next, err := hook.KeyValue.Update(ctx, key, value, revision)
	if err == nil && hook.loseUpdate {
		hook.loseUpdate = false
		return 0, errors.New("simulated lost acknowledgement")
	}
	return next, err
}

func (hook *hookedKV) Get(ctx context.Context, key string) (natsjs.KeyValueEntry, error) {
	hook.gets++
	return hook.KeyValue.Get(ctx, key)
}

func TestAmbiguousAcknowledgementsUseOneReconciliationRead(t *testing.T) {
	connection := startServer(t, "14317")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, testConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	nonceHook := &hookedKV{KeyValue: store.nonces.(natsjs.KeyValue), loseCreate: true}
	store.nonces = nonceHook
	if outcome, err := store.Consume(ctx, testKey, coordination.NonceValue{ValueDigest: testValue, ExpiresAt: now.Add(30 * time.Second), Epoch: 1}); err != nil || outcome != coordination.NonceConsumed {
		t.Fatalf("ambiguous nonce: %q, %v", outcome, err)
	}
	if nonceHook.creates != 1 || nonceHook.gets != 1 {
		t.Fatalf("nonce calls: create=%d get=%d", nonceHook.creates, nonceHook.gets)
	}

	leaseHook := &hookedKV{KeyValue: store.leases.(natsjs.KeyValue), loseCreate: true}
	store.leases = leaseHook
	held, err := store.Acquire(ctx, testKey, coordination.LeaseValue{HolderDigest: testHolder, ExpiresAt: now.Add(30 * time.Second), Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if leaseHook.creates != 1 || leaseHook.gets != 1 {
		t.Fatalf("lease create calls: create=%d get=%d", leaseHook.creates, leaseHook.gets)
	}
	leaseHook.loseUpdate, leaseHook.gets = true, 0
	if err := held.Renew(ctx, now.Add(40*time.Second)); err != nil {
		t.Fatalf("ambiguous renew: %v", err)
	}
	if leaseHook.updates != 1 || leaseHook.gets != 1 {
		t.Fatalf("renew calls: update=%d get=%d", leaseHook.updates, leaseHook.gets)
	}
	leaseHook.loseUpdate, leaseHook.updates, leaseHook.gets = true, 0, 0
	if err := held.Release(ctx); err != nil {
		t.Fatalf("ambiguous release: %v", err)
	}
	if leaseHook.updates != 1 || leaseHook.gets != 1 {
		t.Fatalf("release calls: update=%d get=%d", leaseHook.updates, leaseHook.gets)
	}
}

func TestTimeoutFailsClosedWithBoundedCalls(t *testing.T) {
	now := time.Now().UTC()
	failure := &failingKV{}
	store := &Store{nonces: failure, leases: failure, config: testConfig(1), now: func() time.Time { return now }}
	_, err := store.Consume(context.Background(), testKey, coordination.NonceValue{ValueDigest: testValue, ExpiresAt: now.Add(30 * time.Second), Epoch: 1})
	if !errors.Is(err, coordination.ErrUnavailable) || failure.creates != 1 || failure.gets != 1 {
		t.Fatalf("nonce timeout: %v, create=%d get=%d", err, failure.creates, failure.gets)
	}
	failure.gets = 0
	held := &lease{store: store, key: testKey, holder: testHolder, expires: now.Add(20 * time.Second), revision: 7}
	if err := held.Renew(context.Background(), now.Add(30*time.Second)); !errors.Is(err, coordination.ErrUnavailable) {
		t.Fatalf("lease timeout: %v", err)
	}
	if failure.updates != 1 || failure.gets != 1 {
		t.Fatalf("lease timeout calls: update=%d get=%d", failure.updates, failure.gets)
	}
}

func TestOpenRejectsMismatchedBucket(t *testing.T) {
	connection := startServer(t, "14314")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config := testConfig(1)
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
	config := testConfig(1)
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

func TestRetentionMustExceedLifetimeAndReplayWindow(t *testing.T) {
	config := testConfig(1)
	config.Retention = config.MaxLifetime + config.ReplaySafetyWindow
	if _, err := Open(context.Background(), &nats.Conn{}, config); !errors.Is(err, coordination.ErrInvalidArgument) {
		t.Fatalf("undersized retention: %v", err)
	}
}

type statusFixture struct {
	info *natsjs.StreamInfo
	name string
}

func (fixture statusFixture) Bucket() string                 { return fixture.name }
func (fixture statusFixture) Values() uint64                 { return 0 }
func (fixture statusFixture) History() int64                 { return fixture.info.Config.MaxMsgsPerSubject }
func (fixture statusFixture) TTL() time.Duration             { return fixture.info.Config.MaxAge }
func (fixture statusFixture) BackingStore() string           { return "JetStream" }
func (fixture statusFixture) Bytes() uint64                  { return 0 }
func (fixture statusFixture) IsCompressed() bool             { return false }
func (fixture statusFixture) LimitMarkerTTL() time.Duration  { return 0 }
func (fixture statusFixture) Metadata() map[string]string    { return fixture.info.Config.Metadata }
func (fixture statusFixture) StreamInfo() *natsjs.StreamInfo { return fixture.info }

func TestConfigurationProfileIsExactAndReplicaExplicit(t *testing.T) {
	config := testConfig(9)
	config.Replicas = 3
	expectedConfig := expected(LeaseBucket, "test", config)
	streamConfig := natsjs.StreamConfig{
		Name:              "KV_" + LeaseBucket,
		Description:       "test",
		Subjects:          []string{"$KV." + LeaseBucket + ".>"},
		Retention:         natsjs.LimitsPolicy,
		Discard:           natsjs.DiscardNew,
		MaxConsumers:      -1,
		MaxMsgs:           -1,
		MaxBytes:          -1,
		MaxMsgsPerSubject: int64(expectedConfig.History),
		MaxAge:            expectedConfig.TTL,
		MaxMsgSize:        expectedConfig.MaxValueSize,
		Storage:           expectedConfig.Storage,
		Replicas:          expectedConfig.Replicas,
		Metadata:          expectedConfig.Metadata,
		DenyDelete:        true,
		AllowRollup:       true,
		AllowDirect:       true,
	}
	fixture := statusFixture{info: &natsjs.StreamInfo{Config: streamConfig}, name: LeaseBucket}
	if !matchingStatus(fixture, expectedConfig) {
		t.Fatal("exact replica profile rejected")
	}
	mutations := []func(*natsjs.StreamConfig){
		func(value *natsjs.StreamConfig) { value.Replicas-- },
		func(value *natsjs.StreamConfig) { value.Storage = natsjs.MemoryStorage },
		func(value *natsjs.StreamConfig) {
			value.Metadata = map[string]string{"yukh.adapter": "coordination-kv", "yukh.adapter.version": "1", "yukh.epoch": "9", "foreign": "unexpected"}
		},
		func(value *natsjs.StreamConfig) {
			value.RePublish = &natsjs.RePublish{Source: ">", Destination: "elsewhere"}
		},
		func(value *natsjs.StreamConfig) { value.Sources = []*natsjs.StreamSource{{Name: "foreign"}} },
	}
	for index, mutate := range mutations {
		changed := streamConfig
		mutate(&changed)
		if matchingStatus(statusFixture{info: &natsjs.StreamInfo{Config: changed}, name: LeaseBucket}, expectedConfig) {
			t.Fatalf("mismatched profile %d accepted", index)
		}
	}
}

func testConfig(epoch uint64) Config {
	return Config{Replicas: 1, Bootstrap: true, MaxLifetime: time.Minute, ReplaySafetyWindow: 5 * time.Minute, Retention: time.Hour, Epoch: epoch}
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
