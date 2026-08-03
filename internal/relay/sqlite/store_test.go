package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	relaysqlite "github.com/nomed/yukh-coordination/internal/relay/sqlite"
)

var testChannel = relay.Channel{
	Key: relay.ChannelKey{TenantID: "tenant:test", ChannelID: "channel:test", TranscriptEpoch: "epoch:1"}, URI: "https://coord.example/channels/test",
	CanonicalMetadata: []byte(`{"specversion":"0.1"}`), MetadataDigest: "sha256:test", Lifecycle: "active",
}

func TestDurableAppendRetryAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store := openStore(t, path)
	createChannel(t, store, testChannel)
	firstIntent := intent(testChannel.Key, "event-1")
	first, err := store.Append(context.Background(), firstIntent, prepare(firstIntent))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openStore(t, path)
	t.Cleanup(func() { _ = store.Close() })
	attachment := relay.SignatureAttachment{
		Channel: testChannel.Key, ReceiptID: first.Record.ReceiptID,
		UnsignedReceiptPreimage: first.Record.UnsignedReceiptPreimage,
		Signature:               []byte("signature-1"),
	}
	if _, err := store.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	duplicate, err := store.Append(context.Background(), firstIntent, func(uint64, string) (relay.AcceptedRecord, error) {
		t.Fatal("durable retry must not prepare another record")
		return relay.AcceptedRecord{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.Outcome != relay.AppendOutcomeDuplicate || duplicate.Record.ReceiptID != first.Record.ReceiptID {
		t.Fatalf("retry lost committed identity: %#v", duplicate)
	}
	if string(duplicate.Record.Signature) != "signature-1" {
		t.Fatalf("retry lost durable signature: %#v", duplicate.Record)
	}
	if _, err := store.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatalf("exact signature retry failed: %v", err)
	}
	attachment.Signature = []byte("changed-signature")
	if _, err := store.AttachSignature(context.Background(), attachment); !errors.Is(err, relay.ErrSignatureCollision) {
		t.Fatalf("expected signature collision, got %v", err)
	}

	secondIntent := intent(testChannel.Key, "event-2")
	second, err := store.Append(context.Background(), secondIntent, prepare(secondIntent))
	if err != nil {
		t.Fatal(err)
	}
	if second.Record.Sequence != 2 {
		t.Fatalf("restart changed sequence: got %d", second.Record.Sequence)
	}
	records, err := store.Read(context.Background(), testChannel.Key, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("unexpected replay after restart: %#v", records)
	}
}

func TestCollisionRollbackAndEpochIsolation(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "relay.db"))
	t.Cleanup(func() { _ = store.Close() })
	createChannel(t, store, testChannel)

	failed := intent(testChannel.Key, "failed")
	_, err := store.Append(context.Background(), failed, func(uint64, string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{}, errors.New("selected key unavailable")
	})
	if err == nil {
		t.Fatal("expected preparation failure")
	}

	accepted := intent(testChannel.Key, "event-1")
	result, err := store.Append(context.Background(), accepted, prepare(accepted))
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Sequence != 1 {
		t.Fatalf("rolled-back append consumed sequence: %d", result.Record.Sequence)
	}
	changed := accepted
	changed.CanonicalEvent = []byte(`{"id":"event-1","changed":true}`)
	if _, err := store.Append(context.Background(), changed, prepare(changed)); !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("expected collision, got %v", err)
	}
	duplicateReceipt := intent(testChannel.Key, "event-2")
	_, err = store.Append(context.Background(), duplicateReceipt, func(sequence uint64, digest string) (relay.AcceptedRecord, error) {
		record, err := prepare(duplicateReceipt)(sequence, digest)
		record.ReceiptID = result.Record.ReceiptID
		return record, err
	})
	if err == nil {
		t.Fatal("expected duplicate receipt identity rejection")
	}
	afterRejectedReceipt := intent(testChannel.Key, "event-3")
	afterResult, err := store.Append(context.Background(), afterRejectedReceipt, prepare(afterRejectedReceipt))
	if err != nil {
		t.Fatal(err)
	}
	if afterResult.Record.Sequence != 2 {
		t.Fatalf("rejected receipt consumed sequence: %d", afterResult.Record.Sequence)
	}

	secondEpoch := testChannel
	secondEpoch.Key.TranscriptEpoch = "epoch:2"
	createChannel(t, store, secondEpoch)
	reused := accepted
	reused.Channel = secondEpoch.Key
	if _, err := store.Append(context.Background(), reused, prepare(reused)); !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("expected cross-epoch collision, got %v", err)
	}

	otherTenant := testChannel
	otherTenant.Key.TenantID = "tenant:other"
	createChannel(t, store, otherTenant)
	otherIntent := intent(otherTenant.Key, "event-1")
	if _, err := store.Append(context.Background(), otherIntent, prepare(otherIntent)); err != nil {
		t.Fatal(err)
	}
	otherRecords, err := store.Read(context.Background(), otherTenant.Key, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherRecords) != 1 || otherRecords[0].Channel.TenantID != otherTenant.Key.TenantID {
		t.Fatalf("cross-tenant replay leak: %#v", otherRecords)
	}
}

func TestChannelIdentityIsImmutable(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "relay.db"))
	t.Cleanup(func() { _ = store.Close() })
	createChannel(t, store, testChannel)
	createChannel(t, store, testChannel)

	changedURI := testChannel
	changedURI.Key.TranscriptEpoch = "epoch:2"
	changedURI.URI = "https://coord.example/channels/changed"
	if err := store.CreateChannel(context.Background(), changedURI); !errors.Is(err, relay.ErrChannelConflict) {
		t.Fatalf("expected immutable channel conflict, got %v", err)
	}

	changedID := testChannel
	changedID.Key.ChannelID = "channel:other"
	if err := store.CreateChannel(context.Background(), changedID); !errors.Is(err, relay.ErrChannelConflict) {
		t.Fatalf("expected immutable URI conflict, got %v", err)
	}
}

func TestConcurrentAppendsAreGapFree(t *testing.T) {
	store := openStore(t, filepath.Join(t.TempDir(), "relay.db"))
	t.Cleanup(func() { _ = store.Close() })
	createChannel(t, store, testChannel)

	const count = 32
	sequences := make(chan int, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			appendIntent := intent(testChannel.Key, fmt.Sprintf("event-%03d", i))
			result, err := store.Append(context.Background(), appendIntent, prepare(appendIntent))
			if err != nil {
				errs <- err
				return
			}
			sequences <- int(result.Record.Sequence)
		}()
	}
	wg.Wait()
	close(sequences)
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	actual := make([]int, 0, count)
	for sequence := range sequences {
		actual = append(actual, sequence)
	}
	sort.Ints(actual)
	for i, sequence := range actual {
		if sequence != i+1 {
			t.Fatalf("sequence %d: got %d", i+1, sequence)
		}
	}
}

func TestAbruptProcessExitRecovery(t *testing.T) {
	for _, mode := range []string{"after-commit", "during-prepare"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "relay.db")
			command := exec.Command(os.Args[0], "-test.run=TestSQLiteCrashHelper")
			command.Env = append(os.Environ(), "YUKH_SQLITE_CRASH_HELPER=1", "YUKH_SQLITE_CRASH_MODE="+mode, "YUKH_SQLITE_PATH="+path)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("crash helper: %v\n%s", err, output)
			}

			store := openStore(t, path)
			defer store.Close()
			records, err := store.Read(context.Background(), testChannel.Key, 0, 10)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "after-commit" {
				if len(records) != 1 || records[0].Sequence != 1 {
					t.Fatalf("committed record lost after process exit: %#v", records)
				}
				return
			}
			if len(records) != 0 {
				t.Fatalf("uncommitted record survived process exit: %#v", records)
			}
			next := intent(testChannel.Key, "event-after-recovery")
			result, err := store.Append(context.Background(), next, prepare(next))
			if err != nil {
				t.Fatal(err)
			}
			if result.Record.Sequence != 1 {
				t.Fatalf("crashed transaction consumed sequence: %d", result.Record.Sequence)
			}
		})
	}
}

func TestSQLiteCrashHelper(t *testing.T) {
	if os.Getenv("YUKH_SQLITE_CRASH_HELPER") != "1" {
		return
	}
	store, err := relaysqlite.Open(os.Getenv("YUKH_SQLITE_PATH"))
	if err != nil {
		panic(err)
	}
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		panic(err)
	}
	appendIntent := intent(testChannel.Key, "event-before-crash")
	if os.Getenv("YUKH_SQLITE_CRASH_MODE") == "during-prepare" {
		_, _ = store.Append(context.Background(), appendIntent, func(uint64, string) (relay.AcceptedRecord, error) {
			os.Exit(0)
			return relay.AcceptedRecord{}, nil
		})
		panic("prepare returned after os.Exit")
	}
	if _, err := store.Append(context.Background(), appendIntent, prepare(appendIntent)); err != nil {
		panic(err)
	}
	os.Exit(0)
}

func openStore(t *testing.T, path string) *relaysqlite.Store {
	t.Helper()
	store, err := relaysqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func createChannel(t *testing.T, store *relaysqlite.Store, channel relay.Channel) {
	t.Helper()
	if err := store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
}

func intent(key relay.ChannelKey, eventID string) relay.AppendIntent {
	return relay.AppendIntent{Channel: key, EventID: eventID, CanonicalEvent: []byte(fmt.Sprintf(`{"id":%q}`, eventID))}
}

func prepare(intent relay.AppendIntent) relay.PrepareRecord {
	return func(sequence uint64, digest string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{
			Channel: intent.Channel, Sequence: sequence, EventID: intent.EventID,
			CanonicalEvent: intent.CanonicalEvent, EventDigest: digest,
			AuthenticatedBinding:    []byte(`{"principal_id":"principal:test"}`),
			AuthorizationBinding:    []byte(`{"decision":"allow"}`),
			ReceiptID:               "receipt-" + intent.Channel.TenantID + "-" + intent.EventID,
			SigningKeyID:            "key-1",
			SignatureAlgorithm:      "Ed25519",
			UnsignedReceiptPreimage: []byte(fmt.Sprintf(`{"server_sequence":"%d"}`, sequence)),
		}, nil
	}
}
