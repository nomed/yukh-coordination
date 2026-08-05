package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
)

// LifecycleBackupCompletion owns only supplied custody evidence and lifecycle
// completion. It has no provider, signing, audit-writing or removal authority.
type LifecycleBackupCompletion struct {
	store           *Store
	receiptVerifier lifecycle.CustodianReceiptVerifier
	auditVerifier   lifecycle.CompletionAuditVerifier
}

var _ lifecycle.TranscriptLifecycleBackupCompletionStore = (*LifecycleBackupCompletion)(nil)

func NewLifecycleBackupCompletion(store *Store, receiptVerifier lifecycle.CustodianReceiptVerifier, auditVerifier lifecycle.CompletionAuditVerifier) (*LifecycleBackupCompletion, error) {
	if store == nil || store.db == nil || nilInterface(receiptVerifier) || nilInterface(auditVerifier) {
		return nil, lifecycle.ErrInvalidContract
	}
	return &LifecycleBackupCompletion{store: store, receiptVerifier: receiptVerifier, auditVerifier: auditVerifier}, nil
}

func (s *LifecycleBackupCompletion) BindBackupObligations(ctx context.Context, set lifecycle.BackupObligationSet) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	canonicalSet, setDigest, err := lifecycle.CanonicalBackupObligationSet(set)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	preflight, found, err := loadLifecycleOperation(ctx, s.store.db, set.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if err := lifecycle.ValidateObligationSetIntent(set, preflight.operation.Intent, preflight.operation.IntentDigest); err != nil {
		return lifecycle.Operation{}, err
	}
	existing, err := loadObligationSet(ctx, s.store.db, set.OperationID)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if existing != nil {
		if !bytes.Equal(existing.canonical, canonicalSet) || existing.digest != setDigest {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		obligations, _, evidenceErr := loadBackupEvidence(ctx, s.store.db, set.OperationID)
		if evidenceErr != nil || !obligationsMatchSet(set, obligations) {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		current, currentFound, currentErr := loadLifecycleOperation(ctx, s.store.db, set.OperationID)
		if currentErr != nil || !currentFound {
			return lifecycle.Operation{}, closedFound(currentErr, currentFound)
		}
		if current.operation.State != lifecycle.BackupsPending && current.operation.State != lifecycle.Completed {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(current.operation), nil
	}
	if preflight.operation.State != lifecycle.PayloadRemoved {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}

	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, set.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if stored.operation.State == lifecycle.BackupsPending || stored.operation.State == lifecycle.Completed {
		concurrent, loadErr := loadObligationSet(ctx, tx.conn, set.OperationID)
		obligations, _, evidenceErr := loadBackupEvidence(ctx, tx.conn, set.OperationID)
		if loadErr != nil || evidenceErr != nil || concurrent == nil || concurrent.digest != setDigest ||
			!bytes.Equal(concurrent.canonical, canonicalSet) || !obligationsMatchSet(set, obligations) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	if !sameOperationSnapshot(preflight, stored) || stored.operation.State != lifecycle.PayloadRemoved {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO lifecycle_backup_obligation_sets
		(operation_id, set_digest, canonical_set) VALUES (?, ?, ?)`, set.OperationID, setDigest, canonicalSet); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	for _, obligation := range set.Obligations {
		canonical, digest, err := lifecycle.CanonicalBackupObligation(obligation)
		if err != nil {
			return lifecycle.Operation{}, lifecycle.ErrInvalidContract
		}
		if _, err := tx.conn.ExecContext(ctx, `INSERT INTO lifecycle_backup_obligations
			(operation_id, domain, obligation_digest, canonical_obligation, deadline, binding_kind, binding_digest)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, obligation.OperationID, string(obligation.Domain), digest, canonical,
			obligation.Deadline, string(obligation.BindingKind), obligation.BindingDigest); err != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations SET state = 'backups_pending'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'payload_removed'`, set.OperationID, set.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.BackupsPending
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecycleBackupCompletion) RecordBackupReceipt(ctx context.Context, receipt lifecycle.CustodianReceipt) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	canonical, digest, _, err := lifecycle.CanonicalCustodianReceipt(receipt)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	preflight, found, err := loadLifecycleOperation(ctx, s.store.db, receipt.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if preflight.operation.IntentDigest != receipt.IntentDigest || (preflight.operation.State != lifecycle.BackupsPending && preflight.operation.State != lifecycle.Completed) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	obligation, obligationBytes, obligationDigest, err := loadObligation(ctx, s.store.db, receipt.OperationID, receipt.Domain)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if lifecycle.ValidateReceiptObligation(receipt, obligation, obligationDigest) != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if err := lifecycle.ValidateCustodianReceiptSignature(ctx, s.receiptVerifier, receipt); err != nil {
		return lifecycle.Operation{}, err
	}
	existing, err := loadReceiptByID(ctx, s.store.db, receipt.ReceiptID)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if existing != nil {
		if existing.digest != digest || !bytes.Equal(existing.canonical, canonical) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		currentOperation, currentFound, currentErr := loadLifecycleOperation(ctx, s.store.db, receipt.OperationID)
		if currentErr != nil || !currentFound {
			return lifecycle.Operation{}, closedFound(currentErr, currentFound)
		}
		return lifecycle.CloneOperation(currentOperation.operation), nil
	}
	if preflight.operation.State != lifecycle.BackupsPending {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}

	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, receipt.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	concurrent, concurrentErr := loadReceiptByID(ctx, tx.conn, receipt.ReceiptID)
	if concurrentErr != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if concurrent != nil {
		if concurrent.digest != digest || !bytes.Equal(concurrent.canonical, canonical) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	current, currentBytes, currentDigest, err := loadObligation(ctx, tx.conn, receipt.OperationID, receipt.Domain)
	if err != nil || !sameOperationSnapshot(preflight, stored) || stored.operation.State != lifecycle.BackupsPending ||
		currentDigest != obligationDigest || !bytes.Equal(currentBytes, obligationBytes) || current != obligation {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO lifecycle_backup_receipts
		(receipt_id, receipt_digest, operation_id, domain, canonical_receipt, evidence_time, outcome)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, receipt.ReceiptID, digest, receipt.OperationID, string(receipt.Domain), canonical,
		receipt.EvidenceTime, string(receipt.Outcome)); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecycleBackupCompletion) InspectBackupRecovery(ctx context.Context, reference lifecycle.OperationReference) (lifecycle.BackupRecovery, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.BackupRecovery{}, err
	}
	if err := lifecycle.ValidateOperationReference(reference); err != nil {
		return lifecycle.BackupRecovery{}, err
	}
	tx, err := s.store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return lifecycle.BackupRecovery{}, lifecycle.ErrUnavailable
	}
	defer tx.Rollback()
	operation, found, err := loadLifecycleOperation(ctx, tx, reference.OperationID)
	if err != nil || !found {
		return lifecycle.BackupRecovery{}, closedFound(err, found)
	}
	if operation.operation.IntentDigest != reference.IntentDigest {
		return lifecycle.BackupRecovery{}, lifecycle.ErrConflict
	}
	set, setErr := loadObligationSet(ctx, tx, reference.OperationID)
	completion, completionErr := loadCompletion(ctx, tx, reference.OperationID)
	if setErr != nil || completionErr != nil || set == nil ||
		operation.operation.State != lifecycle.BackupsPending && operation.operation.State != lifecycle.Completed ||
		operation.operation.State == lifecycle.BackupsPending && completion != nil ||
		operation.operation.State == lifecycle.Completed && completion == nil {
		return corruptRecovery(reference), nil
	}
	obligations, receipts, err := loadBackupEvidence(ctx, tx, reference.OperationID)
	if err != nil {
		return corruptRecovery(reference), nil
	}
	if !obligationSetMatchesEvidence(set, obligations) || completion != nil && !completionReferencesStored(completion.evidence, obligations, receipts) {
		return corruptRecovery(reference), nil
	}
	if tx.Commit() != nil {
		return lifecycle.BackupRecovery{}, lifecycle.ErrUnavailable
	}
	return lifecycle.CloneBackupRecovery(lifecycle.ClassifyBackupRecovery(ctx, reference, obligations, receipts, s.receiptVerifier)), nil
}

func (s *LifecycleBackupCompletion) Complete(ctx context.Context, evidence lifecycle.CompletionEvidence) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	canonical, digest, err := lifecycle.CanonicalCompletionEvidence(evidence)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	preflight, found, err := loadLifecycleOperation(ctx, s.store.db, evidence.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if preflight.operation.IntentDigest != evidence.IntentDigest || preflight.operation.Intent.PolicyDigest != evidence.PolicyDigest ||
		(preflight.operation.State != lifecycle.BackupsPending && preflight.operation.State != lifecycle.Completed) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	set, err := loadObligationSet(ctx, s.store.db, evidence.OperationID)
	if err != nil || set == nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	obligations, receipts, err := loadBackupEvidence(ctx, s.store.db, evidence.OperationID)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if err := lifecycle.ValidateCompletionAgainst(ctx, evidence, obligations, receipts, s.receiptVerifier); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := s.auditVerifier.VerifyLifecycleCompletionAudit(ctx, lifecycle.CloneCompletionEvidence(evidence)); err != nil {
		if errors.Is(err, lifecycle.ErrUnavailable) {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	existing, err := loadCompletion(ctx, s.store.db, evidence.OperationID)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if existing != nil {
		if existing.digest != digest || !bytes.Equal(existing.canonical, canonical) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		currentOperation, currentFound, currentErr := loadLifecycleOperation(ctx, s.store.db, evidence.OperationID)
		if currentErr != nil || !currentFound {
			return lifecycle.Operation{}, closedFound(currentErr, currentFound)
		}
		if currentOperation.operation.State != lifecycle.Completed {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(currentOperation.operation), nil
	}

	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, evidence.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if stored.operation.State == lifecycle.Completed {
		concurrent, loadErr := loadCompletion(ctx, tx.conn, evidence.OperationID)
		if loadErr != nil || concurrent == nil || concurrent.digest != digest || !bytes.Equal(concurrent.canonical, canonical) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	currentSet, err := loadObligationSet(ctx, tx.conn, evidence.OperationID)
	if err != nil || currentSet == nil || !sameOperationSnapshot(preflight, stored) || stored.operation.State != lifecycle.BackupsPending ||
		currentSet.digest != set.digest || !bytes.Equal(currentSet.canonical, set.canonical) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	currentObligations, currentReceipts, err := loadBackupEvidence(ctx, tx.conn, evidence.OperationID)
	if err != nil || !sameBackupEvidence(obligations, receipts, currentObligations, currentReceipts) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	// Pure validation only: external verifiers were called during preflight.
	if !completionReferencesStored(evidence, currentObligations, currentReceipts) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO lifecycle_completions
		(operation_id, completion_digest, canonical_completion, completed_at) VALUES (?, ?, ?, ?)`,
		evidence.OperationID, digest, canonical, evidence.CompletedAt); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations SET state = 'completed'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'backups_pending'`, evidence.OperationID, evidence.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.Completed
	return lifecycle.CloneOperation(stored.operation), nil
}

type canonicalRecord struct {
	canonical []byte
	digest    string
}

type completionRecord struct {
	canonical []byte
	digest    string
	evidence  lifecycle.CompletionEvidence
}

type obligationSetRow struct {
	canonical []byte
	digest    string
}

func loadObligationSet(ctx context.Context, q queryRower, operationID string) (*obligationSetRow, error) {
	var row obligationSetRow
	err := q.QueryRowContext(ctx, `SELECT canonical_set, set_digest FROM lifecycle_backup_obligation_sets WHERE operation_id = ?`, operationID).Scan(&row.canonical, &row.digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var set lifecycle.BackupObligationSet
	canonical, digest, err := decodeObligationSet(row.canonical, &set)
	if err != nil || digest != row.digest || !bytes.Equal(canonical, row.canonical) {
		return nil, lifecycle.ErrUnavailable
	}
	return &row, nil
}

func decodeObligationSet(raw []byte, set *lifecycle.BackupObligationSet) ([]byte, string, error) {
	if lifecycle.ValidateCanonical(raw) != nil || json.Unmarshal(raw, set) != nil {
		return nil, "", lifecycle.ErrInvalidContract
	}
	return lifecycle.CanonicalBackupObligationSet(*set)
}

func loadObligation(ctx context.Context, q queryRower, operationID string, domain lifecycle.BackupDomain) (lifecycle.BackupObligation, []byte, string, error) {
	var value lifecycle.BackupObligation
	var raw []byte
	var digest string
	var storedDomain, deadline, bindingKind, bindingDigest string
	err := q.QueryRowContext(ctx, `SELECT canonical_obligation, obligation_digest, domain, deadline, binding_kind, binding_digest
		FROM lifecycle_backup_obligations WHERE operation_id = ? AND domain = ?`, operationID, string(domain)).Scan(&raw, &digest, &storedDomain, &deadline, &bindingKind, &bindingDigest)
	if err != nil {
		return value, nil, "", err
	}
	if lifecycle.ValidateCanonical(raw) != nil || json.Unmarshal(raw, &value) != nil {
		return value, nil, "", lifecycle.ErrUnavailable
	}
	canonical, actual, err := lifecycle.CanonicalBackupObligation(value)
	if err != nil || actual != digest || !bytes.Equal(canonical, raw) || value.OperationID != operationID || string(value.Domain) != storedDomain ||
		value.Domain != domain || value.Deadline != deadline || string(value.BindingKind) != bindingKind || value.BindingDigest != bindingDigest {
		return value, nil, "", lifecycle.ErrUnavailable
	}
	return value, raw, digest, nil
}

func loadReceiptByID(ctx context.Context, q queryRower, receiptID string) (*canonicalRecord, error) {
	var row canonicalRecord
	var operationID, domain, evidenceTime, outcome string
	err := q.QueryRowContext(ctx, `SELECT canonical_receipt, receipt_digest, operation_id, domain, evidence_time, outcome
		FROM lifecycle_backup_receipts WHERE receipt_id = ?`, receiptID).Scan(&row.canonical, &row.digest, &operationID, &domain, &evidenceTime, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var receipt lifecycle.CustodianReceipt
	if lifecycle.ValidateCanonical(row.canonical) != nil || json.Unmarshal(row.canonical, &receipt) != nil {
		return nil, lifecycle.ErrUnavailable
	}
	canonical, digest, _, canonicalErr := lifecycle.CanonicalCustodianReceipt(receipt)
	if canonicalErr != nil || !bytes.Equal(canonical, row.canonical) || digest != row.digest || receipt.ReceiptID != receiptID ||
		receipt.OperationID != operationID || string(receipt.Domain) != domain || receipt.EvidenceTime != evidenceTime || string(receipt.Outcome) != outcome {
		return nil, lifecycle.ErrUnavailable
	}
	return &row, nil
}

func loadCompletion(ctx context.Context, q queryRower, operationID string) (*completionRecord, error) {
	var row completionRecord
	var completedAt string
	err := q.QueryRowContext(ctx, `SELECT canonical_completion, completion_digest, completed_at FROM lifecycle_completions WHERE operation_id = ?`, operationID).Scan(&row.canonical, &row.digest, &completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lifecycle.ValidateCanonical(row.canonical) != nil || json.Unmarshal(row.canonical, &row.evidence) != nil {
		return nil, lifecycle.ErrUnavailable
	}
	canonical, digest, canonicalErr := lifecycle.CanonicalCompletionEvidence(row.evidence)
	if canonicalErr != nil || !bytes.Equal(canonical, row.canonical) || digest != row.digest || row.evidence.OperationID != operationID || row.evidence.CompletedAt != completedAt {
		return nil, lifecycle.ErrUnavailable
	}
	return &row, nil
}

type backupEvidenceQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func loadBackupEvidence(ctx context.Context, q backupEvidenceQueryer, operationID string) ([]lifecycle.BackupObligation, []lifecycle.CustodianReceipt, error) {
	rows, err := q.QueryContext(ctx, `SELECT canonical_obligation, obligation_digest, domain, deadline, binding_kind, binding_digest FROM lifecycle_backup_obligations WHERE operation_id = ?
		ORDER BY CASE domain WHEN 'event' THEN 0 WHEN 'identity' THEN 1 ELSE 2 END`, operationID)
	if err != nil {
		return nil, nil, err
	}
	var obligations []lifecycle.BackupObligation
	for rows.Next() {
		var raw []byte
		var storedDigest string
		var domain, deadline, bindingKind, bindingDigest string
		var value lifecycle.BackupObligation
		if rows.Scan(&raw, &storedDigest, &domain, &deadline, &bindingKind, &bindingDigest) != nil || lifecycle.ValidateCanonical(raw) != nil || json.Unmarshal(raw, &value) != nil {
			rows.Close()
			return nil, nil, lifecycle.ErrUnavailable
		}
		canonical, digest, err := lifecycle.CanonicalBackupObligation(value)
		if err != nil || digest != storedDigest || !bytes.Equal(canonical, raw) || string(value.Domain) != domain ||
			value.Deadline != deadline || string(value.BindingKind) != bindingKind || value.BindingDigest != bindingDigest {
			rows.Close()
			return nil, nil, lifecycle.ErrUnavailable
		}
		obligations = append(obligations, value)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	rows, err = q.QueryContext(ctx, `SELECT canonical_receipt, receipt_digest, receipt_id, domain, evidence_time, outcome FROM lifecycle_backup_receipts WHERE operation_id = ? ORDER BY rowid`, operationID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var receipts []lifecycle.CustodianReceipt
	for rows.Next() {
		var raw []byte
		var storedDigest string
		var receiptID, domain, evidenceTime, outcome string
		var value lifecycle.CustodianReceipt
		if rows.Scan(&raw, &storedDigest, &receiptID, &domain, &evidenceTime, &outcome) != nil || lifecycle.ValidateCanonical(raw) != nil || json.Unmarshal(raw, &value) != nil {
			return nil, nil, lifecycle.ErrUnavailable
		}
		canonical, digest, _, err := lifecycle.CanonicalCustodianReceipt(value)
		if err != nil || digest != storedDigest || !bytes.Equal(canonical, raw) || value.ReceiptID != receiptID || value.OperationID != operationID ||
			string(value.Domain) != domain || value.EvidenceTime != evidenceTime || string(value.Outcome) != outcome {
			return nil, nil, lifecycle.ErrUnavailable
		}
		receipts = append(receipts, value)
	}
	return obligations, receipts, rows.Err()
}

func obligationsMatchSet(set lifecycle.BackupObligationSet, obligations []lifecycle.BackupObligation) bool {
	if len(obligations) != len(set.Obligations) {
		return false
	}
	for i := range obligations {
		left, leftDigest, leftErr := lifecycle.CanonicalBackupObligation(set.Obligations[i])
		right, rightDigest, rightErr := lifecycle.CanonicalBackupObligation(obligations[i])
		if leftErr != nil || rightErr != nil || leftDigest != rightDigest || !bytes.Equal(left, right) {
			return false
		}
	}
	return true
}

func obligationSetMatchesEvidence(row *obligationSetRow, obligations []lifecycle.BackupObligation) bool {
	if row == nil {
		return false
	}
	var set lifecycle.BackupObligationSet
	canonical, digest, err := decodeObligationSet(row.canonical, &set)
	return err == nil && digest == row.digest && bytes.Equal(canonical, row.canonical) && obligationsMatchSet(set, obligations)
}

func sameOperationSnapshot(a, b lifecycleOperationRow) bool {
	return a.operation.IntentDigest == b.operation.IntentDigest && a.operation.State == b.operation.State &&
		bytes.Equal(a.canonicalIntent, b.canonicalIntent) && bytes.Equal(a.operation.Marker, b.operation.Marker) &&
		bytes.Equal(a.operation.Receipt, b.operation.Receipt) && bytes.Equal(a.operation.Signature, b.operation.Signature) &&
		a.payloadRemovalDigest == b.payloadRemovalDigest
}

func sameBackupEvidence(aO []lifecycle.BackupObligation, aR []lifecycle.CustodianReceipt, bO []lifecycle.BackupObligation, bR []lifecycle.CustodianReceipt) bool {
	if len(aO) != len(bO) || len(aR) != len(bR) {
		return false
	}
	for i := range aO {
		ca, da, _ := lifecycle.CanonicalBackupObligation(aO[i])
		cb, db, _ := lifecycle.CanonicalBackupObligation(bO[i])
		if da != db || !bytes.Equal(ca, cb) {
			return false
		}
	}
	for i := range aR {
		ca, da, _, _ := lifecycle.CanonicalCustodianReceipt(aR[i])
		cb, db, _, _ := lifecycle.CanonicalCustodianReceipt(bR[i])
		if da != db || !bytes.Equal(ca, cb) {
			return false
		}
	}
	return true
}

func completionReferencesStored(e lifecycle.CompletionEvidence, obligations []lifecycle.BackupObligation, receipts []lifecycle.CustodianReceipt) bool {
	if len(obligations) != 3 || len(receipts) != 3 || len(e.Receipts) != 3 {
		return false
	}
	byDomain := make(map[lifecycle.BackupDomain]lifecycle.CustodianReceipt, 3)
	for _, receipt := range receipts {
		byDomain[receipt.Domain] = receipt
	}
	for _, ref := range e.Receipts {
		receipt, ok := byDomain[ref.Domain]
		if !ok {
			return false
		}
		_, digest, _, err := lifecycle.CanonicalCustodianReceipt(receipt)
		if err != nil || ref.ReceiptID != receipt.ReceiptID || ref.ReceiptDigest != digest || receipt.Outcome != lifecycle.BackupSucceeded || receipt.EvidenceTime > obligations[indexBackupDomain(ref.Domain)].Deadline || e.CompletedAt < receipt.EvidenceTime {
			return false
		}
	}
	return true
}

func indexBackupDomain(domain lifecycle.BackupDomain) int {
	if domain == lifecycle.EventBackupDomain {
		return 0
	}
	if domain == lifecycle.IdentityBackupDomain {
		return 1
	}
	return 2
}

func corruptRecovery(reference lifecycle.OperationReference) lifecycle.BackupRecovery {
	return lifecycle.BackupRecovery{Profile: lifecycle.BackupRecoveryProfile, OperationID: reference.OperationID, IntentDigest: reference.IntentDigest, Status: lifecycle.RecoveryCorrupt, Findings: []lifecycle.RecoveryFinding{{Domain: lifecycle.EventBackupDomain, Reason: lifecycle.RecoveryInvalidEvidence}}}
}
