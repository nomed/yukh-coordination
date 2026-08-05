package sqlite

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
)

type databaseReceiptVerifier struct {
	store  *Store
	result error
}

func (v databaseReceiptVerifier) VerifyCustodianReceipt(ctx context.Context, _ string, _ string, _ []byte, _ []byte) error {
	if v.result != nil {
		return v.result
	}
	var version int
	if err := v.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 6 {
		return lifecycle.ErrUnavailable
	}
	return nil
}

type databaseAuditVerifier struct {
	store  *Store
	result error
	calls  *int
}

func (v databaseAuditVerifier) VerifyLifecycleCompletionAudit(ctx context.Context, _ lifecycle.CompletionEvidence) error {
	if v.calls != nil {
		*v.calls++
	}
	if v.result != nil {
		return v.result
	}
	var version int
	if err := v.store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 6 {
		return lifecycle.ErrUnavailable
	}
	return nil
}

func TestLifecycleBackupCompletionPersistsExactEvidenceAcrossRestart(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	receiptVerifier := databaseReceiptVerifier{store: fixture.store}
	auditCalls := 0
	adapter, err := NewLifecycleBackupCompletion(fixture.store, receiptVerifier, databaseAuditVerifier{store: fixture.store, calls: &auditCalls})
	if err != nil {
		t.Fatal(err)
	}
	set := backupObligationSet(t, operation)
	bound, err := adapter.BindBackupObligations(context.Background(), set)
	if err != nil || bound.State != lifecycle.BackupsPending {
		t.Fatalf("bind: state=%s err=%v", bound.State, err)
	}
	if retry, err := adapter.BindBackupObligations(context.Background(), set); err != nil || retry.State != lifecycle.BackupsPending {
		t.Fatalf("bind retry: state=%s err=%v", retry.State, err)
	}

	receipts := make([]lifecycle.CustodianReceipt, 3)
	for i, obligation := range set.Obligations {
		receipts[i] = backupReceipt(t, obligation, i)
		if recorded, err := adapter.RecordBackupReceipt(context.Background(), receipts[i]); err != nil || recorded.State != lifecycle.BackupsPending {
			t.Fatalf("record %d: state=%s err=%v", i, recorded.State, err)
		}
		if _, err := adapter.RecordBackupReceipt(context.Background(), receipts[i]); err != nil {
			t.Fatalf("receipt retry %d: %v", i, err)
		}
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	recovery, err := adapter.InspectBackupRecovery(context.Background(), reference)
	if err != nil || recovery.Status != lifecycle.RecoveryCompletable {
		t.Fatalf("recovery: %+v err=%v", recovery, err)
	}
	evidence := completionEvidence(t, operation, receipts)
	completed, err := adapter.Complete(context.Background(), evidence)
	if err != nil || completed.State != lifecycle.Completed || auditCalls != 1 {
		t.Fatalf("complete: state=%s audit=%d err=%v", completed.State, auditCalls, err)
	}
	if retry, err := adapter.Complete(context.Background(), evidence); err != nil || retry.State != lifecycle.Completed || auditCalls != 2 {
		t.Fatalf("complete retry: state=%s audit=%d err=%v", retry.State, auditCalls, err)
	}
	for _, statement := range []string{`UPDATE lifecycle_completions SET completed_at = completed_at`, `DELETE FROM lifecycle_completions`} {
		if _, err := fixture.store.db.Exec(statement); err == nil {
			t.Fatalf("immutable completion accepted %q", statement)
		}
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.store = nil
	reopened, err := Open(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := NewLifecycleBackupCompletion(reopened, databaseReceiptVerifier{store: reopened}, databaseAuditVerifier{store: reopened})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.InspectBackupRecovery(context.Background(), reference); err != nil || got.Status != lifecycle.RecoveryCompletable {
		t.Fatalf("restart recovery: %+v err=%v", got, err)
	}
	if got, err := restarted.Complete(context.Background(), evidence); err != nil || got.State != lifecycle.Completed {
		t.Fatalf("restart completion: state=%s err=%v", got.State, err)
	}
}

func TestLifecycleBackupCompletionFailsClosedWithoutVerifiedExactEvidence(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	set := backupObligationSet(t, operation)
	unavailable, err := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store, result: lifecycle.ErrUnavailable}, databaseAuditVerifier{store: fixture.store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unavailable.RecordBackupReceipt(context.Background(), backupReceipt(t, set.Obligations[0], 0)); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("receipt before set: %v", err)
	}
	valid, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	if _, err := valid.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if _, err := unavailable.RecordBackupReceipt(context.Background(), backupReceipt(t, set.Obligations[0], 0)); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("unavailable verification: %v", err)
	}
	assertTableCount(t, fixture.store, "lifecycle_backup_receipts", 0)
	changed := set
	changed.Obligations = append([]lifecycle.BackupObligation(nil), set.Obligations...)
	changed.Obligations[0].BindingDigest = digestOf('f')
	if _, err := valid.BindBackupObligations(context.Background(), changed); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("changed set retry: %v", err)
	}
}

func TestLifecycleBackupCompletionKeepsFailureAndMixedFindings(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	failed := backupReceipt(t, set.Obligations[0], 0)
	failed.Outcome = lifecycle.BackupFailed
	if _, err := adapter.RecordBackupReceipt(context.Background(), failed); err != nil {
		t.Fatal(err)
	}
	later := backupReceipt(t, set.Obligations[0], 9)
	later.EvidenceTime = "2026-08-04T06:01:31.000Z"
	if _, err := adapter.RecordBackupReceipt(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	got, err := adapter.InspectBackupRecovery(context.Background(), reference)
	want := []lifecycle.RecoveryFinding{{Domain: lifecycle.EventBackupDomain, Reason: lifecycle.RecoveryContradictoryEvidence}, {Domain: lifecycle.IdentityBackupDomain, Reason: lifecycle.RecoveryEvidenceMissing}, {Domain: lifecycle.AuditBackupDomain, Reason: lifecycle.RecoveryEvidenceMissing}}
	if err != nil || got.Status != lifecycle.RecoveryIncident || !reflect.DeepEqual(got.Findings, want) {
		t.Fatalf("mixed findings: %+v err=%v", got, err)
	}
}

func TestLifecycleBackupCompletionConcurrentExactBindConverges(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	const workers = 8
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := adapter.BindBackupObligations(context.Background(), set)
			if err == nil && got.State != lifecycle.BackupsPending {
				err = fmt.Errorf("state %s", got.State)
			}
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent bind: %v", err)
		}
	}
	assertTableCount(t, fixture.store, "lifecycle_backup_obligation_sets", 1)
	assertTableCount(t, fixture.store, "lifecycle_backup_obligations", 3)
}

func TestLifecycleBackupCompletionConcurrentReceiptAndCompletionConverge(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	first := backupReceipt(t, set.Obligations[0], 0)
	runConcurrent(t, 8, func() error {
		got, err := adapter.RecordBackupReceipt(context.Background(), first)
		if err == nil && got.State != lifecycle.BackupsPending {
			return fmt.Errorf("receipt state %s", got.State)
		}
		return err
	})
	assertTableCount(t, fixture.store, "lifecycle_backup_receipts", 1)
	receipts := []lifecycle.CustodianReceipt{first, backupReceipt(t, set.Obligations[1], 1), backupReceipt(t, set.Obligations[2], 2)}
	for _, receipt := range receipts[1:] {
		if _, err := adapter.RecordBackupReceipt(context.Background(), receipt); err != nil {
			t.Fatal(err)
		}
	}
	evidence := completionEvidence(t, operation, receipts)
	runConcurrent(t, 8, func() error {
		got, err := adapter.Complete(context.Background(), evidence)
		if err == nil && got.State != lifecycle.Completed {
			return fmt.Errorf("completion state %s", got.State)
		}
		return err
	})
	assertTableCount(t, fixture.store, "lifecycle_completions", 1)
	assertOperationState(t, fixture.store, operation.Intent.OperationID, lifecycle.Completed)
}

func TestLifecycleBackupCompletionRollsBackSetAndCompletion(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := fixture.store.db.Exec(`CREATE TRIGGER fail_obligation BEFORE INSERT ON lifecycle_backup_obligations BEGIN SELECT RAISE(ABORT, 'forced'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.BindBackupObligations(context.Background(), set); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("forced set rollback: %v", err)
	}
	assertTableCount(t, fixture.store, "lifecycle_backup_obligation_sets", 0)
	assertTableCount(t, fixture.store, "lifecycle_backup_obligations", 0)
	assertOperationState(t, fixture.store, operation.Intent.OperationID, lifecycle.PayloadRemoved)
}

func TestLifecycleBackupCompletionRollsBackReceiptAndCompletionBoundaries(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON lifecycle_backup_receipts BEGIN SELECT RAISE(ABORT, 'forced'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.RecordBackupReceipt(context.Background(), backupReceipt(t, set.Obligations[0], 0)); !errors.Is(err, lifecycle.ErrConflict) {
		t.Fatalf("forced receipt rollback: %v", err)
	}
	assertTableCount(t, fixture.store, "lifecycle_backup_receipts", 0)
	if _, err := fixture.store.db.Exec(`DROP TRIGGER fail_receipt`); err != nil {
		t.Fatal(err)
	}
	receipts := make([]lifecycle.CustodianReceipt, 3)
	for i, obligation := range set.Obligations {
		receipts[i] = backupReceipt(t, obligation, i)
		if _, err := adapter.RecordBackupReceipt(context.Background(), receipts[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.store.db.Exec(`CREATE TRIGGER fail_completion_state BEFORE UPDATE OF state ON lifecycle_operations WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT, 'forced'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Complete(context.Background(), completionEvidence(t, operation, receipts)); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("forced completion rollback: %v", err)
	}
	assertTableCount(t, fixture.store, "lifecycle_completions", 0)
	assertOperationState(t, fixture.store, operation.Intent.OperationID, lifecycle.BackupsPending)
}

func TestLifecycleBackupCompletionSchemaIsImmutableAndCorruptionIsBounded(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	receipt := backupReceipt(t, set.Obligations[0], 0)
	if _, err := adapter.RecordBackupReceipt(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE lifecycle_backup_obligation_sets SET set_digest = set_digest`,
		`DELETE FROM lifecycle_backup_obligation_sets`,
		`UPDATE lifecycle_backup_obligations SET deadline = deadline`,
		`DELETE FROM lifecycle_backup_obligations`,
		`UPDATE lifecycle_backup_receipts SET outcome = outcome`,
		`DELETE FROM lifecycle_backup_receipts`,
	} {
		if _, err := fixture.store.db.Exec(statement); err == nil {
			t.Fatalf("immutable schema accepted %q", statement)
		}
	}
	if _, err := fixture.store.db.Exec(`DROP TRIGGER lifecycle_backup_obligations_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`UPDATE lifecycle_backup_obligations SET deadline = '2026-08-08T00:00:00.000Z' WHERE operation_id = ? AND domain = 'event'`, operation.Intent.OperationID); err != nil {
		t.Fatal(err)
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	recovery, err := adapter.InspectBackupRecovery(context.Background(), reference)
	if err != nil || recovery.Status != lifecycle.RecoveryCorrupt || len(recovery.Findings) != 1 || recovery.Findings[0].Reason != lifecycle.RecoveryInvalidEvidence {
		t.Fatalf("bounded corruption: %+v err=%v", recovery, err)
	}
}

func TestLifecycleBackupCompletionRejectsCompletedStateWithoutEvidence(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	receipts := make([]lifecycle.CustodianReceipt, 3)
	for i, obligation := range set.Obligations {
		receipts[i] = backupReceipt(t, obligation, i)
		if _, err := adapter.RecordBackupReceipt(context.Background(), receipts[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adapter.Complete(context.Background(), completionEvidence(t, operation, receipts)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`DROP TRIGGER lifecycle_completions_no_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.Exec(`DELETE FROM lifecycle_completions WHERE operation_id = ?`, operation.Intent.OperationID); err != nil {
		t.Fatal(err)
	}
	reference := lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest}
	recovery, err := adapter.InspectBackupRecovery(context.Background(), reference)
	if err != nil || recovery.Status != lifecycle.RecoveryCorrupt {
		t.Fatalf("missing completion: %+v err=%v", recovery, err)
	}
}

func TestLifecycleBackupCompletionAuditUnavailabilityDoesNotComplete(t *testing.T) {
	fixture, operation := removedLifecycleOperation(t)
	adapter, _ := NewLifecycleBackupCompletion(fixture.store, databaseReceiptVerifier{store: fixture.store}, databaseAuditVerifier{store: fixture.store, result: lifecycle.ErrUnavailable})
	set := backupObligationSet(t, operation)
	if _, err := adapter.BindBackupObligations(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	receipts := make([]lifecycle.CustodianReceipt, 3)
	for i, obligation := range set.Obligations {
		receipts[i] = backupReceipt(t, obligation, i)
		if _, err := adapter.RecordBackupReceipt(context.Background(), receipts[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := adapter.Complete(context.Background(), completionEvidence(t, operation, receipts)); !errors.Is(err, lifecycle.ErrUnavailable) {
		t.Fatalf("audit unavailable: %v", err)
	}
	assertTableCount(t, fixture.store, "lifecycle_completions", 0)
	assertOperationState(t, fixture.store, operation.Intent.OperationID, lifecycle.BackupsPending)
}

func TestLifecycleBackupCompletionCapabilitySegregation(t *testing.T) {
	adapterType := reflect.TypeOf((*LifecycleBackupCompletion)(nil))
	for _, forbidden := range []reflect.Type{
		reflect.TypeOf((*lifecycle.TranscriptLifecyclePreparationStore)(nil)).Elem(),
		reflect.TypeOf((*lifecycle.TranscriptLifecycleSignatureRemovalStore)(nil)).Elem(),
		reflect.TypeOf((*relay.Store)(nil)).Elem(),
	} {
		if adapterType.Implements(forbidden) {
			t.Fatalf("backup adapter implements forbidden capability %s", forbidden)
		}
	}
}

func removedLifecycleOperation(t *testing.T) (*lifecycleFixture, lifecycle.Operation) {
	t.Helper()
	fixture := newLifecycleFixture(t)
	operation := prepareLifecycleMarker(t, fixture)
	remover, privateKey, _ := newLifecycleRemover(t, fixture.store)
	attachment := signedLifecycleAttachment(t, fixture.preimage, operation, privateKey)
	if _, err := remover.AttachSignature(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	removed, err := remover.RemovePayload(context.Background(), lifecycle.OperationReference{OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, removed
}

func backupObligationSet(t *testing.T, operation lifecycle.Operation) lifecycle.BackupObligationSet {
	t.Helper()
	domains := []lifecycle.BackupDomain{lifecycle.EventBackupDomain, lifecycle.IdentityBackupDomain, lifecycle.AuditBackupDomain}
	obligations := make([]lifecycle.BackupObligation, 3)
	for i, domain := range domains {
		obligations[i] = lifecycle.BackupObligation{Profile: lifecycle.BackupObligationProfile, OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest, PolicyDigest: operation.Intent.PolicyDigest, Domain: domain, Deadline: operation.Intent.ExpectedBackupDeletionWindows[i].Deadline, BindingKind: lifecycle.BackupGeneration, BindingDigest: digestOf(byte('a' + i))}
	}
	set := lifecycle.BackupObligationSet{Profile: lifecycle.BackupObligationSetProfile, OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest, PolicyDigest: operation.Intent.PolicyDigest, Obligations: obligations}
	if _, _, err := lifecycle.CanonicalBackupObligationSet(set); err != nil {
		t.Fatal(err)
	}
	return set
}

func backupReceipt(t *testing.T, obligation lifecycle.BackupObligation, index int) lifecycle.CustodianReceipt {
	t.Helper()
	_, obligationDigest, err := lifecycle.CanonicalBackupObligation(obligation)
	if err != nil {
		t.Fatal(err)
	}
	return lifecycle.CustodianReceipt{Profile: lifecycle.CustodianReceiptProfile, ReceiptID: fmt.Sprintf("0198cf64-cc00-7000-8000-00000000001%d", index), ObligationDigest: obligationDigest, OperationID: obligation.OperationID, IntentDigest: obligation.IntentDigest, PolicyDigest: obligation.PolicyDigest, Domain: obligation.Domain, BackupIdentityDigest: obligation.BindingDigest, EvidenceTime: "2026-08-04T06:01:30.000Z", Method: lifecycle.GenerationRetired, Outcome: lifecycle.BackupSucceeded, CustodianReference: "custodian:" + string(obligation.Domain), VerificationKeyID: "backup-key-1", SignatureAlgorithm: "ed25519", DetachedSignature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
}

func completionEvidence(t *testing.T, operation lifecycle.Operation, receipts []lifecycle.CustodianReceipt) lifecycle.CompletionEvidence {
	t.Helper()
	references := make([]lifecycle.ReceiptEvidence, 3)
	for i, receipt := range receipts {
		_, digest, _, err := lifecycle.CanonicalCustodianReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		references[i] = lifecycle.ReceiptEvidence{Domain: receipt.Domain, ReceiptID: receipt.ReceiptID, ReceiptDigest: digest}
	}
	return lifecycle.CompletionEvidence{Profile: lifecycle.CompletionEvidenceProfile, OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest, PolicyDigest: operation.Intent.PolicyDigest, Receipts: references, SecurityAuditReceipt: "audit:completion", SecurityAuditCheckpoint: "checkpoint:trusted", CompletedAt: "2026-08-04T06:01:40.000Z"}
}

func assertTableCount(t *testing.T, store *Store, table string, want int) {
	t.Helper()
	var got int
	if err := store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s count: got %d want %d", table, got, want)
	}
}
func assertOperationState(t *testing.T, store *Store, operationID string, want lifecycle.SagaState) {
	t.Helper()
	var got string
	if err := store.db.QueryRow("SELECT state FROM lifecycle_operations WHERE operation_id = ?", operationID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("state: got %s want %s", got, want)
	}
}

func runConcurrent(t *testing.T, count int, call func() error) {
	t.Helper()
	results := make(chan error, count)
	var wait sync.WaitGroup
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func() { defer wait.Done(); results <- call() }()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent exact retry: %v", err)
		}
	}
}
