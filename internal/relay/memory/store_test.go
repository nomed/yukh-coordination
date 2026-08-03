package memory_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/memory"
)

var testChannel = relay.Channel{
	Key: relay.ChannelKey{TenantID: "tenant:test", ChannelID: "channel:test", TranscriptEpoch: "epoch:1"},
	URI: "https://coord.example/channels/test",
}

func TestAppendIsIdempotentAndRejectsCollision(t *testing.T) {
	store := newStore(t)
	intent := relay.AppendIntent{Channel: testChannel.Key, EventID: "event-1", CanonicalEvent: []byte(`{"id":"event-1"}`)}

	first, err := store.Append(context.Background(), intent, prepare(intent))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append(context.Background(), intent, func(uint64, string) (relay.AcceptedRecord, error) {
		t.Fatal("duplicate append must not prepare a new record")
		return relay.AcceptedRecord{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != relay.AppendOutcomeAppended || second.Outcome != relay.AppendOutcomeDuplicate {
		t.Fatalf("unexpected outcomes: %q, %q", first.Outcome, second.Outcome)
	}
	if first.Record.Sequence != second.Record.Sequence || first.Record.ReceiptID != second.Record.ReceiptID {
		t.Fatal("duplicate did not return the original committed identity")
	}

	collision := intent
	collision.CanonicalEvent = []byte(`{"id":"event-1","changed":true}`)
	_, err = store.Append(context.Background(), collision, prepare(collision))
	if !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("expected event ID collision, got %v", err)
	}
}

func TestPreparationFailureDoesNotConsumeSequence(t *testing.T) {
	store := newStore(t)
	failed := relay.AppendIntent{Channel: testChannel.Key, EventID: "failed", CanonicalEvent: []byte(`{"id":"failed"}`)}
	_, err := store.Append(context.Background(), failed, func(uint64, string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{}, errors.New("signing key unavailable")
	})
	if err == nil {
		t.Fatal("expected preparation error")
	}

	next := relay.AppendIntent{Channel: testChannel.Key, EventID: "next", CanonicalEvent: []byte(`{"id":"next"}`)}
	result, err := store.Append(context.Background(), next, prepare(next))
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Sequence != 1 {
		t.Fatalf("failed append consumed sequence: got %d", result.Record.Sequence)
	}
}

func TestChannelURIAndEventIDsRemainStableAcrossEpochs(t *testing.T) {
	store := newStore(t)
	secondEpoch := testChannel
	secondEpoch.Key.TranscriptEpoch = "epoch:2"
	if err := store.CreateChannel(context.Background(), secondEpoch); err != nil {
		t.Fatal(err)
	}

	first := relay.AppendIntent{Channel: testChannel.Key, EventID: "event-1", CanonicalEvent: []byte(`{"id":"event-1"}`)}
	if _, err := store.Append(context.Background(), first, prepare(first)); err != nil {
		t.Fatal(err)
	}
	reused := first
	reused.Channel = secondEpoch.Key
	if _, err := store.Append(context.Background(), reused, prepare(reused)); !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("expected cross-epoch event ID collision, got %v", err)
	}

	changedURI := secondEpoch
	changedURI.Key.TranscriptEpoch = "epoch:3"
	changedURI.URI = "https://coord.example/channels/renamed"
	if err := store.CreateChannel(context.Background(), changedURI); !errors.Is(err, relay.ErrChannelConflict) {
		t.Fatalf("expected immutable URI conflict, got %v", err)
	}
}

func TestConcurrentAppendsAreGapFree(t *testing.T) {
	store := newStore(t)
	const count = 64
	results := make(chan uint64, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup

	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			intent := relay.AppendIntent{
				Channel:        testChannel.Key,
				EventID:        fmt.Sprintf("event-%03d", i),
				CanonicalEvent: []byte(fmt.Sprintf(`{"id":"event-%03d"}`, i)),
			}
			result, err := store.Append(context.Background(), intent, prepare(intent))
			if err != nil {
				errs <- err
				return
			}
			results <- result.Record.Sequence
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	sequences := make([]int, 0, count)
	for sequence := range results {
		sequences = append(sequences, int(sequence))
	}
	sort.Ints(sequences)
	for i, sequence := range sequences {
		if sequence != i+1 {
			t.Fatalf("sequence %d: got %d", i, sequence)
		}
	}
}

func TestReadReturnsOrderedDefensiveCopies(t *testing.T) {
	store := newStore(t)
	for i := 1; i <= 3; i++ {
		intent := relay.AppendIntent{Channel: testChannel.Key, EventID: fmt.Sprintf("event-%d", i), CanonicalEvent: []byte(fmt.Sprintf(`{"id":"event-%d"}`, i))}
		if _, err := store.Append(context.Background(), intent, prepare(intent)); err != nil {
			t.Fatal(err)
		}
	}

	records, err := store.Read(context.Background(), testChannel.Key, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sequence != 2 || records[1].Sequence != 3 {
		t.Fatalf("unexpected replay: %#v", records)
	}
	records[0].CanonicalEvent[0] = 'x'
	again, err := store.Read(context.Background(), testChannel.Key, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].CanonicalEvent[0] == 'x' {
		t.Fatal("caller mutated committed record")
	}
	beyond, err := store.Read(context.Background(), testChannel.Key, ^uint64(0), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(beyond) != 0 {
		t.Fatalf("expected empty replay beyond high-water mark, got %#v", beyond)
	}
}

func newStore(t *testing.T) *memory.Store {
	t.Helper()
	store := memory.New()
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	return store
}

func prepare(intent relay.AppendIntent) relay.PrepareRecord {
	return func(sequence uint64, digest string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{
			Channel: intent.Channel, Sequence: sequence, EventID: intent.EventID,
			CanonicalEvent: intent.CanonicalEvent, EventDigest: digest,
			AuthenticatedBinding:    []byte(`{"principal_id":"principal:test"}`),
			AuthorizationBinding:    []byte(`{"decision":"allow"}`),
			ReceiptID:               fmt.Sprintf("receipt-%d", sequence),
			UnsignedReceiptPreimage: []byte(fmt.Sprintf(`{"server_sequence":"%d"}`, sequence)),
		}, nil
	}
}
