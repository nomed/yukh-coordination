package jetstream

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
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/relay"
)

func TestTenantSubjectDoesNotExposeTenant(t *testing.T) {
	subject, err := TenantSubject("tenant:customer-sensitive")
	if err != nil {
		t.Fatal(err)
	}
	if subject == "" || subject == "yukh.coordination.v1.tenant.tenant:customer-sensitive.log" {
		t.Fatalf("unsafe tenant subject %q", subject)
	}
	again, _ := TenantSubject("tenant:customer-sensitive")
	if subject != again {
		t.Fatal("tenant subject is not deterministic")
	}
}

func TestStoreCommandReplayAndOptimisticConcurrency(t *testing.T) {
	connection := startServer(t, "14223")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		t.Fatal(err)
	}
	channel := relay.Channel{Key: relay.ChannelKey{TenantID: "tenant:test", ChannelID: "channel:test", TranscriptEpoch: "epoch:1"}, URI: "https://coord.example/channels/test", CanonicalMetadata: []byte(`{"specversion":"0.1"}`), MetadataDigest: "sha-256:test", Lifecycle: "active"}
	if err := store.CreateChannel(ctx, channel); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateChannel(ctx, channel); err != nil {
		t.Fatalf("exact channel retry: %v", err)
	}

	const count = 24
	sequences := make(chan int, count)
	errs := make(chan error, count)
	var group sync.WaitGroup
	for index := range count {
		group.Add(1)
		go func() {
			defer group.Done()
			intent := testIntent(channel.Key, fmt.Sprintf("event-%02d", index))
			result, appendErr := store.Append(ctx, intent, testPrepare(intent))
			if appendErr != nil {
				errs <- appendErr
				return
			}
			sequences <- int(result.Record.Sequence)
		}()
	}
	group.Wait()
	close(errs)
	close(sequences)
	for appendErr := range errs {
		t.Error(appendErr)
	}
	actual := make([]int, 0, count)
	for sequence := range sequences {
		actual = append(actual, sequence)
	}
	sort.Ints(actual)
	if len(actual) != count {
		t.Fatalf("got %d successful appends", len(actual))
	}
	for index, sequence := range actual {
		if sequence != index+1 {
			t.Fatalf("sequence %d: got %d", index+1, sequence)
		}
	}

	firstIntent := testIntent(channel.Key, "event-00")
	duplicate, err := store.Append(ctx, firstIntent, func(uint64, string) (relay.AcceptedRecord, error) {
		t.Fatal("duplicate invoked preparation")
		return relay.AcceptedRecord{}, nil
	})
	if err != nil || duplicate.Outcome != relay.AppendOutcomeDuplicate {
		t.Fatalf("duplicate: %#v, %v", duplicate, err)
	}
	changed := firstIntent
	changed.CanonicalEvent = []byte(`{"changed":true}`)
	if _, err := store.Append(ctx, changed, testPrepare(changed)); !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("collision: %v", err)
	}

	attachment := relay.SignatureAttachment{Channel: channel.Key, ReceiptID: duplicate.Record.ReceiptID, UnsignedReceiptPreimage: duplicate.Record.UnsignedReceiptPreimage, Signature: []byte("signature")}
	signed, err := store.AttachSignature(ctx, attachment)
	if err != nil {
		t.Fatal(err)
	}
	if string(signed.Signature) != "signature" {
		t.Fatal("signature was not returned")
	}
	if _, err := store.AttachSignature(ctx, attachment); err != nil {
		t.Fatalf("exact signature retry: %v", err)
	}

	lostIntent := testIntent(channel.Key, "event-lost-ack")
	loseNextAcknowledgement(t, store)
	lostResult, err := store.Append(ctx, lostIntent, testPrepare(lostIntent))
	store.publishHook = nil
	if err != nil || lostResult.Record.EventID != lostIntent.EventID {
		t.Fatalf("append lost-ack reconciliation: %#v, %v", lostResult, err)
	}
	lostAttachment := relay.SignatureAttachment{Channel: channel.Key, ReceiptID: lostResult.Record.ReceiptID, UnsignedReceiptPreimage: lostResult.Record.UnsignedReceiptPreimage, Signature: []byte("lost-ack-signature")}
	loseNextAcknowledgement(t, store)
	if _, err := store.AttachSignature(ctx, lostAttachment); err != nil {
		t.Fatalf("signature lost-ack reconciliation: %v", err)
	}
	store.publishHook = nil

	reopened, err := Open(ctx, connection, Config{Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Read(ctx, channel.Key, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != count+1 || string(records[duplicate.Record.Sequence-1].Signature) != "signature" || string(records[lostResult.Record.Sequence-1].Signature) != "lost-ack-signature" {
		t.Fatalf("replay mismatch: %d records", len(records))
	}
}

func loseNextAcknowledgement(t *testing.T, store *Store) {
	t.Helper()
	store.publishHook = func(ctx context.Context, subject string, revision uint64, data []byte) error {
		store.publishHook = nil
		if _, err := store.js.Publish(ctx, subject, data, natsjs.WithExpectStream(StreamName), natsjs.WithExpectLastSequencePerSubject(revision)); err != nil {
			return err
		}
		return errors.New("simulated lost acknowledgement")
	}
}

func TestReducerRejectsTenantSubjectMismatch(t *testing.T) {
	connection := startServer(t, "14224")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := newCommand("tenant:foreign", commandChannelCreated, channelPayload{CanonicalMetadata: encodeBytes([]byte(`{}`)), ChannelID: "channel", Lifecycle: "active", MetadataDigest: "sha-256:test", TranscriptEpoch: "epoch", URI: "https://example.test/channel"})
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := TenantSubject("tenant:victim")
	if _, err := store.js.Publish(ctx, subject, foreign, natsjs.WithExpectLastSequencePerSubject(0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.load(ctx, "tenant:victim"); err == nil {
		t.Fatal("hostile tenant command was accepted")
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

func testIntent(key relay.ChannelKey, eventID string) relay.AppendIntent {
	return relay.AppendIntent{Channel: key, EventID: eventID, CanonicalEvent: []byte(fmt.Sprintf(`{"id":%q}`, eventID))}
}

func testPrepare(intent relay.AppendIntent) relay.PrepareRecord {
	return func(sequence uint64, digest string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{Channel: intent.Channel, Sequence: sequence, EventID: intent.EventID, CanonicalEvent: intent.CanonicalEvent, EventDigest: digest, AuthenticatedBinding: []byte(`{"principal":"test"}`), AuthorizationBinding: []byte(`{"decision":"allow"}`), ReceiptID: "receipt-" + intent.EventID, SigningKeyID: "key-1", SignatureAlgorithm: "Ed25519", UnsignedReceiptPreimage: []byte(fmt.Sprintf(`{"sequence":%d}`, sequence))}, nil
	}
}

func TestOpenBootstrapsAndRejectsMismatchedRealStream(t *testing.T) {
	server := os.Getenv("YUKH_NATS_SERVER")
	if server == "" {
		t.Skip("YUKH_NATS_SERVER is not set")
	}
	port := "14222"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true}); err != nil {
		t.Fatal(err)
	}
	js, _ := natsjs.New(connection)
	if _, err := js.Stream(ctx, StreamName); err != nil {
		t.Fatal(err)
	}
	config := ExpectedStreamConfig(1)
	config.MaxMsgSize--
	if _, err := js.UpdateStream(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, connection, Config{Replicas: 1}); err == nil {
		t.Fatal("mismatched stream accepted")
	}
}
