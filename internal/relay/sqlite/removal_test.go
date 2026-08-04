package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
)

type lifecycleTestVerifier struct {
	key       ed25519.PublicKey
	reject    bool
	lastBytes []byte
}

func (v *lifecycleTestVerifier) VerifyLifecycleReceipt(_ context.Context, keyID, algorithm string, preimage, signature []byte) error {
	v.lastBytes = bytes.Clone(preimage)
	if v.reject || keyID != "lifecycle-key-1" || algorithm != "ed25519" || !ed25519.Verify(v.key, preimage, signature) {
		return errors.New("private verifier detail")
	}
	return nil
}

func TestLifecycleSignatureAndSelectiveRemovalAreExactAndDurable(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, verifier := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)

	signed, err := remover.AttachSignature(context.Background(), attachment)
	if err != nil || signed.State != lifecycle.ReceiptSigned || !bytes.Equal(signed.Signature, attachment.Signature) {
		t.Fatalf("attach signature: operation=%#v err=%v", signed, err)
	}
	if retry, err := remover.AttachSignature(context.Background(), attachment); err != nil || !reflect.DeepEqual(retry, signed) {
		t.Fatalf("exact signature retry changed outcome: operation=%#v err=%v", retry, err)
	}
	if len(verifier.lastBytes) == 0 {
		t.Fatal("verifier did not receive the domain-separated receipt preimage")
	}

	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	removed, err := remover.RemovePayload(context.Background(), reference)
	if err != nil || removed.State != lifecycle.PayloadRemoved {
		t.Fatalf("remove payload: operation=%#v err=%v", removed, err)
	}
	if retry, err := remover.RemovePayload(context.Background(), reference); err != nil || !reflect.DeepEqual(retry, removed) {
		t.Fatalf("exact removal retry changed outcome: operation=%#v err=%v", retry, err)
	}
	assertRemovalCounts(t, fixture.store, 2, 2)
	assertRemainingSequences(t, fixture.store, map[uint64][]byte{1: fixture.payloads[0], 3: fixture.payloads[2]})
	replayed, err := fixture.store.Read(context.Background(), fixtureChannelKey(), 0, 10)
	if err != nil || len(replayed) != 1 || replayed[0].Sequence != 1 || !bytes.Equal(replayed[0].CanonicalEvent, fixture.payloads[0]) {
		t.Fatalf("redacted replay crossed first removed sequence: records=%#v err=%v", replayed, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.store = nil
	reopened, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	restarted, err := NewLifecycleSignatureRemoval(reopened, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := restarted.RemovePayload(context.Background(), reference); err != nil || retry.State != lifecycle.PayloadRemoved || !bytes.Equal(retry.Signature, attachment.Signature) {
		t.Fatalf("restart lost removal identity: operation=%#v err=%v", retry, err)
	}
	assertRemovalCounts(t, reopened, 2, 2)
}

func TestLifecycleVerifierFailureAndChangedSignaturePreservePayload(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	rejecting := &lifecycleTestVerifier{key: privateKey.Public().(ed25519.PublicKey), reject: true}
	remover, err := NewLifecycleSignatureRemoval(fixture.store, rejecting)
	if err != nil {
		t.Fatal(err)
	}
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); !errors.Is(err, lifecycle.ErrUnavailable) || err.Error() != lifecycle.ErrUnavailable.Error() {
		t.Fatalf("verifier detail leaked or failed open: %v", err)
	}
	assertPayloads(t, fixture.store, fixture.payloads)
	inspected, err := fixture.preparation.Inspect(context.Background(), operation.Intent.OperationID)
	if err != nil || inspected.State != lifecycle.MarkerPersisted || len(inspected.Signature) != 0 {
		t.Fatalf("verification failure advanced state: operation=%#v err=%v", inspected, err)
	}

	valid, _, _ := newLifecycleRemover(t, fixture.store)
	if _, err := valid.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	changed := attachment
	changed.Signature = bytes.Repeat([]byte{9}, ed25519.SignatureSize)
	if _, err := valid.AttachSignature(context.Background(), changed); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("changed signature retry did not conflict: %v", err)
	}
	assertPayloads(t, fixture.store, fixture.payloads)
}

func TestLifecycleRemovalRollbackRestoresRowsAndState(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, _ := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`CREATE TRIGGER force_removal_rollback BEFORE UPDATE OF state ON lifecycle_operations
		WHEN NEW.state = 'payload_removed' BEGIN SELECT RAISE(ABORT, 'forced rollback'); END`); err != nil {
		t.Fatal(err)
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	if _, err := remover.RemovePayload(context.Background(), reference); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("forced removal rollback was not closed: %v", err)
	}
	if _, err := fixture.store.db.Exec(`DROP TRIGGER force_removal_rollback`); err != nil {
		t.Fatal(err)
	}
	assertPayloads(t, fixture.store, fixture.payloads)
	assertRemovalCounts(t, fixture.store, 4, 0)
	inspected, err := fixture.preparation.Inspect(context.Background(), operation.Intent.OperationID)
	if err != nil || inspected.State != lifecycle.ReceiptSigned {
		t.Fatalf("rollback leaked state: operation=%#v err=%v", inspected, err)
	}
}

func TestLifecycleRemovalRetryReverifiesPersistedSignature(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, _ := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	if _, err := remover.RemovePayload(context.Background(), reference); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE lifecycle_operations SET receipt_signature = ? WHERE operation_id = ?`, bytes.Repeat([]byte{9}, ed25519.SignatureSize), operation.Intent.OperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := remover.RemovePayload(context.Background(), reference); !errors.Is(err, lifecycle.ErrUnavailable) || err.Error() != lifecycle.ErrUnavailable.Error() {
		t.Fatalf("tampered persisted signature passed retry or leaked detail: %v", err)
	}
}

func TestWholeDeletionRemovesEpochAndPreservesIdentifierNonReuse(t *testing.T) {
	fixture := newLifecycleFixture(t)
	intent, marker, preimage := wholeDeletionMaterial(t, fixture)
	fixture.intent, fixture.marker, fixture.preimage = intent, marker, preimage
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, _ := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if _, err := remover.RemovePayload(context.Background(), lifecycle.OperationReference{OperationID: intent.OperationID, IntentDigest: operation.IntentDigest}); err != nil {
		t.Fatal(err)
	}
	assertRemovalCounts(t, fixture.store, 0, 4)
	reads, err := fixture.store.Read(context.Background(), fixtureChannelKey(), 0, 10)
	if err != nil || len(reads) != 0 {
		t.Fatalf("deleted epoch returned records: records=%#v err=%v", reads, err)
	}

	var metadata, metadataDigest []byte
	var uri string
	if err := fixture.store.db.QueryRow(`SELECT t.canonical_metadata, t.metadata_digest, i.uri
		FROM transcripts t JOIN channel_identities i USING (tenant_id, channel_id)
		WHERE t.tenant_id = ? AND t.channel_id = ? AND t.transcript_epoch = '1'`, "tenant-alpha", "channel-release").Scan(&metadata, &metadataDigest, &uri); err != nil {
		t.Fatal(err)
	}
	successor := relay.Channel{Key: relay.ChannelKey{TenantID: "tenant-alpha", ChannelID: "channel-release", TranscriptEpoch: "2"}, URI: uri, CanonicalMetadata: metadata, MetadataDigest: string(metadataDigest), Lifecycle: "active"}
	if err := fixture.store.CreateChannel(context.Background(), successor); err != nil {
		t.Fatal(err)
	}
	reused := relay.AppendIntent{Channel: successor.Key, EventID: "event-1", CanonicalEvent: fixture.payloads[0]}
	if _, err := fixture.store.Append(context.Background(), reused, fixtureRecord(reused, "receipt:new")); !errors.Is(err, relay.ErrEventIDCollision) {
		t.Fatalf("deleted event identifier was reused: %v", err)
	}
}

func TestLifecycleRemovalCapabilityHasNoBackupOrSigningAuthority(t *testing.T) {
	candidate := reflect.TypeOf((*LifecycleSignatureRemoval)(nil))
	if candidate.Implements(reflect.TypeOf((*lifecycle.TranscriptLifecycleBackupCompletionStore)(nil)).Elem()) ||
		candidate.Implements(reflect.TypeOf((*lifecycle.TranscriptLifecycleStore)(nil)).Elem()) {
		t.Fatal("signature/removal adapter acquired backup or aggregate authority")
	}
	for _, method := range []string{"RecordBackupReceipt", "Complete", "Sign"} {
		if _, found := candidate.MethodByName(method); found {
			t.Fatalf("signature/removal adapter exposes %s", method)
		}
	}
}

func TestLifecycleRemovalScansTheCompleteSQLiteFailureDomainWithoutClaimingSanitization(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, _ := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if _, err := remover.RemovePayload(context.Background(), lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}); err != nil {
		t.Fatal(err)
	}
	for _, canary := range [][]byte{fixture.payloads[1], fixture.payloads[3]} {
		var logicalCount int
		if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM accepted_records WHERE canonical_event = ?`, canary).Scan(&logicalCount); err != nil || logicalCount != 0 {
			t.Fatalf("removed canary remains logically addressable: count=%d err=%v", logicalCount, err)
		}
		physicalResidual := false
		for _, path := range []string{fixture.path, fixture.path + "-wal", fixture.path + "-shm"} {
			body, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				t.Fatal(err)
			}
			physicalResidual = physicalResidual || bytes.Contains(body, canary)
		}
		t.Logf("logical canary removed; physical SQLite failure-domain residual observed=%v", physicalResidual)
	}
}

func prepareLifecycleMarker(t *testing.T, fixture *lifecycleFixture) lifecycle.Operation {
	t.Helper()
	reserved, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	evidence := lifecycle.ExportEvidence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, ManifestDigest: digestOf('a'), CustodyReceiptDigest: digestOf('b')}
	if _, err := fixture.preparation.BindExport(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	persistence := lifecycle.MarkerPersistence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, CanonicalMarker: fixture.marker, CanonicalPreimage: fixture.preimage}
	operation, err := fixture.preparation.PersistMarker(context.Background(), persistence)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func newLifecycleRemover(t *testing.T, store *Store) (*LifecycleSignatureRemoval, ed25519.PrivateKey, *lifecycleTestVerifier) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	verifier := &lifecycleTestVerifier{key: privateKey.Public().(ed25519.PublicKey)}
	remover, err := NewLifecycleSignatureRemoval(store, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return remover, privateKey, verifier
}

func signedLifecycleAttachment(t *testing.T, preimage []byte, operation lifecycle.Operation, privateKey ed25519.PrivateKey) lifecycle.SignatureAttachment {
	t.Helper()
	var receipt lifecycle.ReceiptPreimage
	if err := json.Unmarshal(preimage, &receipt); err != nil {
		t.Fatal(err)
	}
	_, signing, err := lifecycle.CanonicalReceiptPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle.SignatureAttachment{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest, ReceiptPreimage: bytes.Clone(preimage), Signature: ed25519.Sign(privateKey, signing)}
}

func wholeDeletionMaterial(t *testing.T, fixture *lifecycleFixture) (lifecycle.Intent, []byte, []byte) {
	t.Helper()
	intent := fixture.intent
	intent.Action = lifecycle.DeleteTranscript
	intent.Target = lifecycle.Target{Kind: lifecycle.TargetTranscript}
	_, intentDigest, err := lifecycle.CanonicalIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	var marker lifecycle.Marker
	var receipt lifecycle.ReceiptPreimage
	if json.Unmarshal(fixture.marker, &marker) != nil || json.Unmarshal(fixture.preimage, &receipt) != nil {
		t.Fatal("invalid lifecycle fixture")
	}
	marker.IntentDigest = intentDigest
	marker.Target = intent.Target
	marker.ResultingLifecycle = lifecycle.Deleted
	canonicalMarker, markerDigest, err := lifecycle.CanonicalMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	receipt.IntentDigest = intentDigest
	receipt.MarkerDigest = markerDigest
	receipt.ResultingLifecycle = lifecycle.Deleted
	canonicalReceipt, _, err := lifecycle.CanonicalReceiptPreimage(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return intent, canonicalMarker, canonicalReceipt
}

func assertRemovalCounts(t *testing.T, store *Store, accepted, tombstones int) {
	t.Helper()
	var gotAccepted, gotTombstones int
	if store.db.QueryRow(`SELECT COUNT(*) FROM accepted_records`).Scan(&gotAccepted) != nil || store.db.QueryRow(`SELECT COUNT(*) FROM lifecycle_payload_tombstones`).Scan(&gotTombstones) != nil {
		t.Fatal("cannot inspect removal counts")
	}
	if gotAccepted != accepted || gotTombstones != tombstones {
		t.Fatalf("removal counts: accepted=%d tombstones=%d, want %d/%d", gotAccepted, gotTombstones, accepted, tombstones)
	}
}

func assertRemainingSequences(t *testing.T, store *Store, want map[uint64][]byte) {
	t.Helper()
	rows, err := store.db.Query(`SELECT server_sequence, canonical_event FROM accepted_records ORDER BY server_sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[uint64][]byte{}
	for rows.Next() {
		var sequence uint64
		var payload []byte
		if rows.Scan(&sequence, &payload) != nil {
			t.Fatal("cannot inspect remaining payload")
		}
		got[sequence] = payload
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("non-target payload changed: got=%#v want=%#v", got, want)
	}
}
