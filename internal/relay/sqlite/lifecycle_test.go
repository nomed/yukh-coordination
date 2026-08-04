package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

type lifecycleVectors struct {
	Policy          string `json:"policy"`
	Intent          string `json:"intent"`
	Marker          string `json:"marker"`
	ReceiptPreimage string `json:"receipt_preimage"`
}

type lifecycleFixture struct {
	path        string
	store       *Store
	preparation *LifecyclePreparation
	policy      lifecycle.Policy
	intent      lifecycle.Intent
	marker      []byte
	preimage    []byte
	payloads    [][]byte
}

func TestLifecyclePreparationPersistsExactRetriesAndAtomicFence(t *testing.T) {
	fixture := newLifecycleFixture(t)
	operation, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil || operation.State != lifecycle.Reserved {
		t.Fatalf("reserve: operation=%#v err=%v", operation, err)
	}
	if retry, err := fixture.preparation.Reserve(context.Background(), fixture.intent); err != nil || !reflect.DeepEqual(retry, operation) {
		t.Fatalf("exact reservation retry changed result: operation=%#v err=%v", retry, err)
	}

	evidence := lifecycle.ExportEvidence{
		OperationID: fixture.intent.OperationID, IntentDigest: operation.IntentDigest,
		ManifestDigest: digestOf('a'), CustodyReceiptDigest: digestOf('b'),
	}
	bound, err := fixture.preparation.BindExport(context.Background(), evidence)
	if err != nil || bound.State != lifecycle.ExportSatisfied {
		t.Fatalf("bind export: operation=%#v err=%v", bound, err)
	}
	if retry, err := fixture.preparation.BindExport(context.Background(), evidence); err != nil || retry.State != lifecycle.ExportSatisfied {
		t.Fatalf("exact export retry failed: operation=%#v err=%v", retry, err)
	}

	persistence := lifecycle.MarkerPersistence{
		OperationID: fixture.intent.OperationID, IntentDigest: operation.IntentDigest,
		CanonicalMarker: fixture.marker, CanonicalPreimage: fixture.preimage,
	}
	persisted, err := fixture.preparation.PersistMarker(context.Background(), persistence)
	if err != nil || persisted.State != lifecycle.MarkerPersisted {
		t.Fatalf("persist marker: operation=%#v err=%v", persisted, err)
	}
	if retry, err := fixture.preparation.PersistMarker(context.Background(), persistence); err != nil || !reflect.DeepEqual(retry, persisted) {
		t.Fatalf("exact marker retry changed result: operation=%#v err=%v", retry, err)
	}
	assertTranscriptState(t, fixture.store, "redacted", "incomplete")
	assertPayloads(t, fixture.store, fixture.payloads)

	appendIntent := relay.AppendIntent{Channel: fixtureChannelKey(), EventID: "event-after-fence", CanonicalEvent: []byte(`{"id":"event-after-fence"}`)}
	if _, err := fixture.store.Append(context.Background(), appendIntent, fixtureRecord(appendIntent, "receipt:after-fence")); !errors.Is(err, relay.ErrTransitionConflict) {
		t.Fatalf("append crossed durable lifecycle fence: %v", err)
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
	preparation, err := NewLifecyclePreparation(reopened, []lifecycle.Policy{fixture.policy})
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := preparation.Inspect(context.Background(), fixture.intent.OperationID)
	if err != nil || !reflect.DeepEqual(inspected, persisted) {
		t.Fatalf("restart changed operation: operation=%#v err=%v", inspected, err)
	}
	assertTranscriptState(t, reopened, "redacted", "incomplete")
	assertPayloads(t, reopened, fixture.payloads)
}

func TestLifecyclePreparationRejectsSkippedExportAndChangedOperations(t *testing.T) {
	fixture := newLifecycleFixture(t)
	reserved, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	persistence := lifecycle.MarkerPersistence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, CanonicalMarker: fixture.marker, CanonicalPreimage: fixture.preimage}
	if _, err := fixture.preparation.PersistMarker(context.Background(), persistence); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("required export was skipped: %v", err)
	}

	changed := fixture.intent
	changed.RequesterRoleID = "role-other"
	if _, err := fixture.preparation.Reserve(context.Background(), changed); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("changed operation ID did not collide: %v", err)
	}
	second := fixture.intent
	second.OperationID = "0198cf64-cc00-7000-8000-000000000003"
	if _, err := fixture.preparation.Reserve(context.Background(), second); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("second active transcript operation was accepted: %v", err)
	}
	inspected, err := fixture.preparation.Inspect(context.Background(), fixture.intent.OperationID)
	if err != nil || inspected.State != lifecycle.Reserved || inspected.IntentDigest != reserved.IntentDigest {
		t.Fatalf("conflicts mutated reservation: operation=%#v err=%v", inspected, err)
	}
	assertTranscriptState(t, fixture.store, "active", "complete")
}

func TestLifecycleMarkerRollbackKeepsTranscriptAndPayloadIntact(t *testing.T) {
	fixture := newLifecycleFixture(t)
	reserved, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	evidence := lifecycle.ExportEvidence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, ManifestDigest: digestOf('a'), CustodyReceiptDigest: digestOf('b')}
	if _, err := fixture.preparation.BindExport(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`CREATE TRIGGER force_marker_rollback BEFORE UPDATE OF state ON lifecycle_operations
		WHEN NEW.state = 'marker_persisted' BEGIN SELECT RAISE(ABORT, 'forced rollback'); END`); err != nil {
		t.Fatal(err)
	}
	persistence := lifecycle.MarkerPersistence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, CanonicalMarker: fixture.marker, CanonicalPreimage: fixture.preimage}
	if _, err := fixture.preparation.PersistMarker(context.Background(), persistence); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("forced transaction failure was not closed: %v", err)
	}
	if _, err := fixture.store.db.Exec(`DROP TRIGGER force_marker_rollback`); err != nil {
		t.Fatal(err)
	}
	assertTranscriptState(t, fixture.store, "active", "complete")
	assertPayloads(t, fixture.store, fixture.payloads)
	operation, err := fixture.preparation.Inspect(context.Background(), fixture.intent.OperationID)
	if err != nil || operation.State != lifecycle.ExportSatisfied || len(operation.Marker) != 0 || len(operation.Receipt) != 0 {
		t.Fatalf("rollback leaked partial lifecycle state: operation=%#v err=%v", operation, err)
	}
}

func TestLifecycleReservationIsConcurrentAndDueInspectionIsBounded(t *testing.T) {
	fixture := newLifecycleFixture(t)
	const callers = 8
	results := make(chan lifecycle.Operation, callers)
	errorsSeen := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			operation, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
			results <- operation
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent exact reserve failed: %v", err)
		}
	}
	for operation := range results {
		if operation.Intent.OperationID != fixture.intent.OperationID || operation.State != lifecycle.Reserved {
			t.Fatalf("concurrent reserve diverged: %#v", operation)
		}
	}
	due, err := fixture.preparation.InspectDue(context.Background(), lifecycle.DueQuery{WallTime: "2026-08-04T06:02:00.000Z", Limit: 1})
	if err != nil || len(due) != 1 || due[0].Intent.OperationID != fixture.intent.OperationID {
		t.Fatalf("bounded due inspection: operations=%#v err=%v", due, err)
	}
	after, err := fixture.preparation.InspectDue(context.Background(), lifecycle.DueQuery{WallTime: "2026-08-04T06:02:00.000Z", AfterOperationID: fixture.intent.OperationID, Limit: 1})
	if err != nil || len(after) != 0 {
		t.Fatalf("due cursor was not stable: operations=%#v err=%v", after, err)
	}
}

func TestLifecyclePreparationFailsClosedOnDamagedCanonicalIntent(t *testing.T) {
	fixture := newLifecycleFixture(t)
	if _, err := fixture.preparation.Reserve(context.Background(), fixture.intent); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE lifecycle_operations SET canonical_intent = ? WHERE operation_id = ?`, []byte(`{"damaged":true}`), fixture.intent.OperationID); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.preparation.Inspect(context.Background(), fixture.intent.OperationID)
	if !errors.Is(err, lifecycle.ErrUnavailable) || err.Error() != lifecycle.ErrUnavailable.Error() {
		t.Fatalf("damaged storage leaked provider detail or failed open: %v", err)
	}
}

func TestLifecyclePreparationFailsClosedOnCrossBoundMarker(t *testing.T) {
	fixture := newLifecycleFixture(t)
	reserved, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	evidence := lifecycle.ExportEvidence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, ManifestDigest: digestOf('a'), CustodyReceiptDigest: digestOf('b')}
	if _, err := fixture.preparation.BindExport(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	persistence := lifecycle.MarkerPersistence{OperationID: fixture.intent.OperationID, IntentDigest: reserved.IntentDigest, CanonicalMarker: fixture.marker, CanonicalPreimage: fixture.preimage}
	if _, err := fixture.preparation.PersistMarker(context.Background(), persistence); err != nil {
		t.Fatal(err)
	}
	var marker lifecycle.Marker
	if err := json.Unmarshal(fixture.marker, &marker); err != nil {
		t.Fatal(err)
	}
	marker.AuthorizingAuditReceipt = "audit:replacement"
	damaged, _, err := lifecycle.CanonicalMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE lifecycle_operations SET canonical_marker = ? WHERE operation_id = ?`, damaged, fixture.intent.OperationID); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.preparation.Inspect(context.Background(), fixture.intent.OperationID)
	if !errors.Is(err, lifecycle.ErrUnavailable) || err.Error() != lifecycle.ErrUnavailable.Error() {
		t.Fatalf("cross-bound durable marker did not fail closed: %v", err)
	}
}

func TestLifecyclePreparationHasNoCompletionCapability(t *testing.T) {
	candidate := reflect.TypeOf((*LifecyclePreparation)(nil))
	if _, found := candidate.MethodByName("AttachSignature"); found {
		t.Fatal("preparation adapter exposes lifecycle signing")
	}
	if _, found := candidate.MethodByName("RemovePayload"); found {
		t.Fatal("preparation adapter exposes payload removal")
	}
	if candidate.Implements(reflect.TypeOf((*lifecycle.TranscriptLifecycleStore)(nil)).Elem()) {
		t.Fatal("preparation adapter implements the destructive aggregate port")
	}
}

func TestLifecyclePreparationPreservesTranscriptEpochZero(t *testing.T) {
	fixture := newLifecycleFixtureAt(t, 0)
	operation, err := fixture.preparation.Reserve(context.Background(), fixture.intent)
	if err != nil || operation.State != lifecycle.Reserved || operation.Intent.Transcript.TranscriptEpoch != 0 {
		t.Fatalf("epoch-zero reservation: operation=%#v err=%v", operation, err)
	}
}

func TestLifecyclePreparationRejectsPolicyEpochMismatch(t *testing.T) {
	fixture := newLifecycleFixture(t)
	changedPolicy := fixture.policy
	changedPolicy.PolicyEpoch = 2
	changedPolicy.PolicyDigest = ""
	digest, err := lifecycle.PolicyDigest(changedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	changedPolicy.PolicyDigest = digest
	preparation, err := NewLifecyclePreparation(fixture.store, []lifecycle.Policy{changedPolicy})
	if err != nil {
		t.Fatal(err)
	}
	changedIntent := fixture.intent
	changedIntent.PolicyEpoch = changedPolicy.PolicyEpoch
	changedIntent.PolicyDigest = changedPolicy.PolicyDigest
	if _, err := preparation.Reserve(context.Background(), changedIntent); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("policy epoch diverged from immutable transcript binding: %v", err)
	}
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	return newLifecycleFixtureAt(t, 1)
}

func newLifecycleFixtureAt(t *testing.T, transcriptEpoch uint64) *lifecycleFixture {
	t.Helper()
	vectorBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "test-vectors", "transcript-lifecycle-0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors lifecycleVectors
	if err := json.Unmarshal(vectorBytes, &vectors); err != nil {
		t.Fatal(err)
	}
	var policy lifecycle.Policy
	var intent lifecycle.Intent
	if json.Unmarshal([]byte(vectors.Policy), &policy) != nil || json.Unmarshal([]byte(vectors.Intent), &intent) != nil {
		t.Fatal("invalid lifecycle test vector")
	}
	intent.Transcript.TranscriptEpoch = transcriptEpoch
	canonicalIntent, intentDigest, err := lifecycle.CanonicalIntent(intent)
	if err != nil {
		t.Fatal(err)
	}
	if transcriptEpoch != 1 {
		vectors.Intent = string(canonicalIntent)
		var marker lifecycle.Marker
		var preimage lifecycle.ReceiptPreimage
		if json.Unmarshal([]byte(vectors.Marker), &marker) != nil || json.Unmarshal([]byte(vectors.ReceiptPreimage), &preimage) != nil {
			t.Fatal("invalid lifecycle marker vector")
		}
		marker.Transcript.TranscriptEpoch = transcriptEpoch
		marker.IntentDigest = intentDigest
		canonicalMarker, markerDigest, err := lifecycle.CanonicalMarker(marker)
		if err != nil {
			t.Fatal(err)
		}
		preimage.Transcript.TranscriptEpoch = transcriptEpoch
		preimage.IntentDigest = intentDigest
		preimage.MarkerDigest = markerDigest
		canonicalPreimage, _, err := lifecycle.CanonicalReceiptPreimage(preimage)
		if err != nil {
			t.Fatal(err)
		}
		vectors.Marker = string(canonicalMarker)
		vectors.ReceiptPreimage = string(canonicalPreimage)
	}
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if store != nil {
			_ = store.Close()
		}
	})
	metadataRaw, err := json.Marshal(map[string]any{
		"specversion": "0.1", "tenant_id": intent.Transcript.TenantID,
		"channel_uri": "https://coord.example/channels/release", "channel_id": intent.Transcript.ChannelID,
		"acl_policy_version": "1", "acl_policy_digest": digestOf('c'),
		"retention_policy_digest": policy.PolicyDigest, "retention_epoch": policy.PolicyEpoch,
		"created_at": "2026-08-03T06:01:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := jsoncanonicalizer.Transform(metadataRaw)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validator.ValidateChannelMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	channel := relay.Channel{Key: relay.ChannelKey{TenantID: "tenant-alpha", ChannelID: "channel-release", TranscriptEpoch: strconv.FormatUint(transcriptEpoch, 10)}, URI: validated.ChannelURI, CanonicalMetadata: metadata, MetadataDigest: validated.Digest, Lifecycle: "active"}
	if err := store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	payloads := make([][]byte, 0, 4)
	for sequence := 1; sequence <= 4; sequence++ {
		payload := []byte(fmt.Sprintf(`{"id":"event-%d","payload":"keep-%d"}`, sequence, sequence))
		payloads = append(payloads, bytes.Clone(payload))
		appendIntent := relay.AppendIntent{Channel: channel.Key, EventID: fmt.Sprintf("event-%d", sequence), CanonicalEvent: payload}
		receiptID := fmt.Sprintf("receipt:event:%d", sequence)
		if sequence == 4 {
			receiptID = intent.HighWaterReceiptReference
		}
		result, err := store.Append(context.Background(), appendIntent, fixtureRecord(appendIntent, receiptID))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.AttachSignature(context.Background(), relay.SignatureAttachment{Channel: channel.Key, ReceiptID: receiptID, UnsignedReceiptPreimage: result.Record.UnsignedReceiptPreimage, Signature: []byte("signed")}); err != nil {
			t.Fatal(err)
		}
	}
	preparation, err := NewLifecyclePreparation(store, []lifecycle.Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	return &lifecycleFixture{path: path, store: store, preparation: preparation, policy: policy, intent: intent, marker: []byte(vectors.Marker), preimage: []byte(vectors.ReceiptPreimage), payloads: payloads}
}

func fixtureChannelKey() relay.ChannelKey {
	return relay.ChannelKey{TenantID: "tenant-alpha", ChannelID: "channel-release", TranscriptEpoch: "1"}
}

func fixtureRecord(intent relay.AppendIntent, receiptID string) relay.PrepareRecord {
	return func(sequence uint64, eventDigest string) (relay.AcceptedRecord, error) {
		return relay.AcceptedRecord{
			Channel: intent.Channel, Sequence: sequence, EventID: intent.EventID,
			CanonicalEvent: intent.CanonicalEvent, EventDigest: eventDigest,
			AuthenticatedBinding: []byte(`{"principal_id":"principal:test"}`), AuthorizationBinding: []byte(`{"decision":"allow"}`),
			ReceiptID: receiptID, SigningKeyID: "key-1", SignatureAlgorithm: "Ed25519",
			UnsignedReceiptPreimage: []byte(fmt.Sprintf(`{"server_sequence":"%d"}`, sequence)),
		}, nil
	}
}

func assertTranscriptState(t *testing.T, store *Store, lifecycleState, completeness string) {
	t.Helper()
	var gotLifecycle, gotCompleteness string
	if err := store.db.QueryRow(`SELECT lifecycle, completeness FROM transcripts WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`, "tenant-alpha", "channel-release", "1").Scan(&gotLifecycle, &gotCompleteness); err != nil {
		t.Fatal(err)
	}
	if gotLifecycle != lifecycleState || gotCompleteness != completeness {
		t.Fatalf("transcript state: got %s/%s, want %s/%s", gotLifecycle, gotCompleteness, lifecycleState, completeness)
	}
}

func assertPayloads(t *testing.T, store *Store, want [][]byte) {
	t.Helper()
	rows, err := store.db.Query(`SELECT canonical_event FROM accepted_records ORDER BY server_sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		got = append(got, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("payload bytes changed: got %q want %q", got, want)
	}
}

func digestOf(value byte) string {
	return "sha-256:" + string(bytes.Repeat([]byte{value}, 64))
}
