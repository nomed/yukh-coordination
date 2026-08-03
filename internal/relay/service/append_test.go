package service_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/memory"
	"github.com/nomed/yukh-coordination/internal/relay/service"
	relaysqlite "github.com/nomed/yukh-coordination/internal/relay/sqlite"
)

var testChannel = relay.Channel{
	Key: relay.ChannelKey{TenantID: "tenant:test", ChannelID: "channel:test", TranscriptEpoch: "epoch:1"}, URI: "https://coord.example/channels/test",
	CanonicalMetadata: []byte(`{"specversion":"0.1"}`), MetadataDigest: "sha256:test", Lifecycle: "active",
}

func TestAppendAcknowledgesOnlyDurableSignature(t *testing.T) {
	store := memory.New()
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	signer := &fakeSigner{}
	appendService, err := service.NewAppendService(store, signer)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("event-1")
	result, err := appendService.Append(context.Background(), intent, prepare(intent))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != relay.AppendOutcomeAppended || len(result.Record.Signature) == 0 {
		t.Fatalf("unsigned success result: %#v", result)
	}
	if signer.selectCalls != 1 || signer.signCalls != 1 {
		t.Fatalf("unexpected signer calls: select=%d sign=%d", signer.selectCalls, signer.signCalls)
	}

	retry, err := appendService.Append(context.Background(), intent, prepare(intent))
	if err != nil {
		t.Fatal(err)
	}
	if retry.Outcome != relay.AppendOutcomeDuplicate || len(retry.Record.Signature) == 0 {
		t.Fatalf("unexpected retry: %#v", retry)
	}
	if signer.selectCalls != 1 || signer.signCalls != 1 {
		t.Fatal("signed retry selected a new key or signed again")
	}
}

func TestExactRetryRecoversPendingSignature(t *testing.T) {
	store := memory.New()
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	failingSigner := &fakeSigner{signErr: errors.New("key temporarily unavailable")}
	firstService, err := service.NewAppendService(store, failingSigner)
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("event-1")
	if _, err := firstService.Append(context.Background(), intent, prepare(intent)); !errors.Is(err, relay.ErrSignaturePending) {
		t.Fatalf("expected pending signature, got %v", err)
	}
	committed, err := store.Lookup(context.Background(), intent.Channel, intent.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if len(committed.Signature) != 0 {
		t.Fatal("failed signer attached a signature")
	}

	recoverySigner := &fakeSigner{}
	recoveryService, err := service.NewAppendService(store, recoverySigner)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := recoveryService.Append(context.Background(), intent, prepare(intent))
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Outcome != relay.AppendOutcomeDuplicate || len(recovered.Record.Signature) == 0 {
		t.Fatalf("retry did not recover signature: %#v", recovered)
	}
	if recoverySigner.selectCalls != 0 || recoverySigner.signCalls != 1 {
		t.Fatal("recovery selected a replacement key instead of using persisted preimage")
	}
}

func TestSelectionFailureCommitsNothing(t *testing.T) {
	store := memory.New()
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	appendService, err := service.NewAppendService(store, &fakeSigner{selectErr: errors.New("no eligible key")})
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("event-1")
	if _, err := appendService.Append(context.Background(), intent, prepare(intent)); err == nil {
		t.Fatal("expected key selection failure")
	}
	if _, err := store.Lookup(context.Background(), intent.Channel, intent.EventID); !errors.Is(err, relay.ErrEventNotFound) {
		t.Fatalf("selection failure committed event: %v", err)
	}
}

func TestPreparedRecordCannotReplaceSigningSelection(t *testing.T) {
	store := memory.New()
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	appendService, err := service.NewAppendService(store, &fakeSigner{})
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("event-1")
	_, err = appendService.Append(context.Background(), intent, func(sequence uint64, digest string, selection service.SigningSelection) (relay.AcceptedRecord, error) {
		record, err := prepare(intent)(sequence, digest, selection)
		record.SigningKeyID = "replacement-key"
		return record, err
	})
	if !errors.Is(err, relay.ErrInvalidArgument) {
		t.Fatalf("expected signing-selection rejection, got %v", err)
	}
	if _, err := store.Lookup(context.Background(), intent.Channel, intent.EventID); !errors.Is(err, relay.ErrEventNotFound) {
		t.Fatalf("invalid signing selection committed event: %v", err)
	}
}

func TestSQLiteRestartRecoversPendingSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := relaysqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateChannel(context.Background(), testChannel); err != nil {
		t.Fatal(err)
	}
	firstService, err := service.NewAppendService(store, &fakeSigner{signErr: errors.New("signer offline")})
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent("event-1")
	if _, err := firstService.Append(context.Background(), intent, prepare(intent)); !errors.Is(err, relay.ErrSignaturePending) {
		t.Fatalf("expected pending signature, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = relaysqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recoverySigner := &fakeSigner{}
	recoveryService, err := service.NewAppendService(store, recoverySigner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := recoveryService.Append(context.Background(), intent, prepare(intent))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != relay.AppendOutcomeDuplicate || len(result.Record.Signature) == 0 {
		t.Fatalf("SQLite recovery returned no signed duplicate: %#v", result)
	}
	if recoverySigner.selectCalls != 0 || recoverySigner.signCalls != 1 {
		t.Fatal("SQLite recovery selected a replacement signing key")
	}
}

type fakeSigner struct {
	selectCalls int
	signCalls   int
	selectErr   error
	signErr     error
}

func (s *fakeSigner) Select(context.Context) (service.SigningSelection, error) {
	s.selectCalls++
	return service.SigningSelection{KeyID: "key-1", Algorithm: "Ed25519"}, s.selectErr
}

func (s *fakeSigner) Sign(_ context.Context, record relay.AcceptedRecord) ([]byte, error) {
	s.signCalls++
	if s.signErr != nil {
		return nil, s.signErr
	}
	return []byte("signed:" + record.ReceiptID), nil
}

func testIntent(eventID string) relay.AppendIntent {
	return relay.AppendIntent{Channel: testChannel.Key, EventID: eventID, CanonicalEvent: []byte(fmt.Sprintf(`{"id":%q}`, eventID))}
}

func prepare(intent relay.AppendIntent) service.PrepareRecord {
	return func(sequence uint64, digest string, selection service.SigningSelection) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{
			Channel: intent.Channel, Sequence: sequence, EventID: intent.EventID,
			CanonicalEvent: intent.CanonicalEvent, EventDigest: digest,
			AuthenticatedBinding:    []byte(`{"principal_id":"principal:test"}`),
			AuthorizationBinding:    []byte(`{"decision":"allow"}`),
			ReceiptID:               "receipt-" + intent.EventID,
			SigningKeyID:            selection.KeyID,
			SignatureAlgorithm:      selection.Algorithm,
			UnsignedReceiptPreimage: []byte(fmt.Sprintf(`{"algorithm":%q,"key_id":%q,"server_sequence":"%d"}`, selection.Algorithm, selection.KeyID, sequence)),
		}, nil
	}
}
