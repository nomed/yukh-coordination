package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"regexp"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

var recoveryReceiptPattern = regexp.MustCompile(`^audit:[A-Za-z0-9._:/-]{1,250}$`)

type RestorePlan struct {
	ledger             *Ledger
	manifest           audit.SignedRecoveryManifest
	identityDatabaseID string
	floors             []identity.EpochFloor
	backupDigest       audit.Hash
}

func (p *RestorePlan) IdentityDatabaseID() string {
	if p == nil {
		return ""
	}
	return p.identityDatabaseID
}
func (p *RestorePlan) EpochFloors() []identity.EpochFloor {
	if p == nil {
		return nil
	}
	return append([]identity.EpochFloor(nil), p.floors...)
}
func (p *RestorePlan) ManifestReference() string {
	if p == nil {
		return ""
	}
	return p.manifest.Reference
}

func (p *RestorePlan) IdentityBackupDigest() audit.Hash {
	if p == nil {
		return audit.Hash{}
	}
	return p.manifest.Manifest.IdentityBackup.Digest
}

func (p *RestorePlan) IdentityBackupID() string {
	if p == nil {
		return ""
	}
	return p.manifest.Manifest.IdentityBackup.BackupID
}

func (p *RestorePlan) IdentityWallHighWater() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.manifest.Manifest.IdentityWallHighWater
}

func (p *RestorePlan) CheckpointReference() string {
	if p == nil {
		return ""
	}
	return p.manifest.Manifest.CheckpointReference
}

func (l *Ledger) CreateRecoveryManifest(ctx context.Context, input audit.RecoveryManifestInput, authority ed25519.PublicKey, signer audit.RecoverySigner) (audit.SignedRecoveryManifest, error) {
	if l == nil || l.db == nil || ctx == nil || signer == nil {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	if err := requireAdmitted(ctx, l.db); err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	selection, err := signer.SelectRecovery(ctx)
	if err != nil || selection.Algorithm != audit.CheckpointAlgorithm {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	key, err := l.latestKey(ctx, selection.KeyID, authority)
	if err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	var ledgerID string
	var available uint64
	if err := l.db.QueryRowContext(ctx, `SELECT ledger_id, merkle_size FROM audit_metadata WHERE singleton = 1`).Scan(&ledgerID, &available); err != nil || ledgerID != input.AuditBackup.DatabaseID || input.AuditBackupTreeSize == 0 || input.AuditBackupTreeSize > available {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	backupHead, err := l.MerkleTreeHead(ctx, input.AuditBackupTreeSize)
	if err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	checkpoint, checkpointVersion, err := readCheckpoint(ctx, l.db, input.CheckpointReference)
	if err != nil || checkpoint.Checkpoint.TreeSize != input.AuditBackupTreeSize || checkpoint.Checkpoint.RootHash != backupHead.Root {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	checkpointKey, err := l.latestKey(ctx, checkpoint.Checkpoint.KeyID, authority)
	if err != nil || checkpointKey.Statement.Version < checkpointVersion {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	trust, err := audit.VerifySignedCheckpoint(checkpoint, checkpointKey.Statement)
	if err != nil || trust != audit.CheckpointTrusted {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	manifest := audit.RecoveryManifest{ManifestID: input.ManifestID, IdentityBackup: input.IdentityBackup, AuditBackup: input.AuditBackup,
		AuditBackupTreeHead: backupHead, CheckpointReference: checkpoint.Reference, CheckpointTreeHead: audit.TreeHead{Size: checkpoint.Checkpoint.TreeSize, Root: checkpoint.Checkpoint.RootHash},
		CheckpointConsistency: audit.ConsistencyProof{FirstSize: backupHead.Size, SecondSize: backupHead.Size}, IdentityEpochFloors: append([]identity.EpochFloor(nil), input.IdentityEpochFloors...),
		IdentityWallHighWater: input.IdentityWallHighWater, CreatedAt: input.CreatedAt, Algorithm: selection.Algorithm, KeyID: selection.KeyID}
	canonical, err := audit.CanonicalRecoveryManifest(manifest)
	if err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	preimage, _ := audit.RecoveryManifestPreimage(canonical)
	signature, err := signer.SignRecovery(ctx, selection, preimage)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return audit.SignedRecoveryManifest{}, audit.ErrUnavailable
	}
	reference, err := audit.RecoveryManifestReference(canonical, signature)
	if err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	signed := audit.SignedRecoveryManifest{Manifest: manifest, Canonical: canonical, Signature: append([]byte(nil), signature...), Reference: reference}
	if err := audit.VerifySignedRecoveryManifest(signed, key.Statement, checkpoint, checkpointKey.Statement); err != nil {
		return audit.SignedRecoveryManifest{}, err
	}
	return signed, nil
}

func (l *Ledger) ValidateRestore(ctx context.Context, signed audit.SignedRecoveryManifest, authority ed25519.PublicKey) (*RestorePlan, error) {
	if l == nil || l.db == nil || ctx == nil {
		return nil, audit.ErrUnavailable
	}
	manifest, err := audit.ParseCanonicalRecoveryManifest(signed.Canonical)
	if err != nil {
		return nil, err
	}
	signed.Manifest = manifest
	manifestKey, err := l.latestKey(ctx, manifest.KeyID, authority)
	if err != nil {
		return nil, err
	}
	checkpoint, checkpointVersion, err := readCheckpoint(ctx, l.db, manifest.CheckpointReference)
	if err != nil {
		return nil, err
	}
	checkpointKey, err := l.latestKey(ctx, checkpoint.Checkpoint.KeyID, authority)
	if err != nil || checkpointKey.Statement.Version < checkpointVersion || audit.VerifySignedRecoveryManifest(signed, manifestKey.Statement, checkpoint, checkpointKey.Statement) != nil {
		return nil, audit.ErrUnavailable
	}
	var ledgerID, fence string
	var size uint64
	var rootRaw, restoreDigest []byte
	var accepted sql.NullString
	if err := l.db.QueryRowContext(ctx, `SELECT m.ledger_id, m.merkle_size, m.merkle_root, o.fence_state, o.restore_backup_digest, o.accepted_manifest_reference FROM audit_metadata m CROSS JOIN audit_operational_state o WHERE m.singleton = 1 AND o.singleton = 1`).Scan(&ledgerID, &size, &rootRaw, &fence, &restoreDigest, &accepted); err != nil || (fence != "restore_fenced" && !(fence == "admitted" && accepted.Valid && accepted.String == signed.Reference)) || ledgerID != manifest.AuditBackup.DatabaseID || size < manifest.AuditBackupTreeHead.Size || len(rootRaw) != sha256.Size || !bytes.Equal(restoreDigest, manifest.AuditBackup.Digest[:]) {
		return nil, audit.ErrUnavailable
	}
	if fence == "restore_fenced" && (size != manifest.AuditBackupTreeHead.Size || !bytes.Equal(rootRaw, manifest.AuditBackupTreeHead.Root[:])) {
		return nil, audit.ErrUnavailable
	}
	return &RestorePlan{ledger: l, manifest: signed, identityDatabaseID: manifest.IdentityBackup.DatabaseID, floors: append([]identity.EpochFloor(nil), manifest.IdentityEpochFloors...), backupDigest: manifest.AuditBackup.Digest}, nil
}

// CommitRestore atomically appends the sole canonical restore_fence record,
// persists its signed manifest and admits the audit ledger. Identity remains
// independently fenced until it consumes the returned durable receipt.
func (l *Ledger) CommitRestore(ctx context.Context, plan *RestorePlan, operationID string, at time.Time) (string, error) {
	if l == nil || l.db == nil || ctx == nil || plan == nil || plan.ledger != l {
		return "", audit.ErrUnavailable
	}
	record := identity.AuditRecord{ProfileVersion: 1, OperationID: operationID, Operation: identity.AuditRestoreFence, Outcome: identity.AuditAllow, Reason: identity.AuditReasonRestoreVerified, DecisionTime: at, CheckpointReference: plan.manifest.Manifest.CheckpointReference, RecoveryReference: plan.manifest.Reference}
	canonical, err := audit.CanonicalRecord(record)
	if err != nil {
		return "", err
	}
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return "", audit.ErrUnavailable
	}
	defer tx.rollback()
	var fence string
	var digest []byte
	var accepted, receipt sql.NullString
	if err := tx.conn.QueryRowContext(ctx, `SELECT fence_state, restore_backup_digest, accepted_manifest_reference, completion_receipt FROM audit_operational_state WHERE singleton = 1`).Scan(&fence, &digest, &accepted, &receipt); err != nil || !bytes.Equal(digest, plan.backupDigest[:]) {
		return "", audit.ErrUnavailable
	}
	if fence == "admitted" && accepted.Valid && accepted.String == plan.manifest.Reference && receipt.Valid {
		return receipt.String, tx.commit(ctx)
	}
	if fence != "restore_fenced" {
		return "", audit.ErrUnavailable
	}
	committed, err := appendRecord(ctx, tx.conn, record, canonical)
	if err != nil {
		return "", err
	}
	reference := committed.Reference()
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO audit_recovery_manifests (manifest_reference, manifest_id, canonical_manifest, signature, checkpoint_reference, completion_receipt) VALUES (?, ?, ?, ?, ?, ?)`, plan.manifest.Reference, plan.manifest.Manifest.ManifestID, plan.manifest.Canonical, plan.manifest.Signature, plan.manifest.Manifest.CheckpointReference, reference); err != nil {
		return "", audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, `UPDATE audit_operational_state SET fence_state = 'admitted', accepted_manifest_reference = ?, external_checkpoint_reference = ?, completion_receipt = ? WHERE singleton = 1 AND fence_state = 'restore_fenced'`, plan.manifest.Reference, plan.manifest.Manifest.CheckpointReference, reference); err != nil {
		return "", audit.ErrUnavailable
	}
	if err := tx.commit(ctx); err != nil {
		return "", audit.ErrUnavailable
	}
	return reference, nil
}

// AcceptedRestore returns the durable completion receipt only when this exact
// plan has already crossed the audit admission boundary.
func (l *Ledger) AcceptedRestore(ctx context.Context, plan *RestorePlan) (string, bool, error) {
	if l == nil || l.db == nil || ctx == nil || plan == nil || plan.ledger != l {
		return "", false, audit.ErrUnavailable
	}
	var fence string
	var accepted, receipt sql.NullString
	if err := l.db.QueryRowContext(ctx, `SELECT fence_state, accepted_manifest_reference, completion_receipt FROM audit_operational_state WHERE singleton = 1`).Scan(&fence, &accepted, &receipt); err != nil {
		return "", false, audit.ErrUnavailable
	}
	if fence == "restore_fenced" {
		return "", false, nil
	}
	if fence != "admitted" || !accepted.Valid || accepted.String != plan.manifest.Reference || !receipt.Valid || !recoveryReceiptPattern.MatchString(receipt.String) {
		return "", false, audit.ErrUnavailable
	}
	return receipt.String, true, nil
}

func (l *Ledger) OperationalReady(ctx context.Context, now time.Time, authority ed25519.PublicKey, policy audit.ReadinessPolicy, signer audit.CheckpointSigner, probe audit.SignerReadiness, witnessVerifier audit.WitnessVerifier) error {
	if l == nil || l.db == nil || ctx == nil || signer == nil || probe == nil || now.Location() != time.UTC || !now.Equal(now.Truncate(time.Millisecond)) || policy.MaximumCheckpointAge <= 0 || policy.MaximumCheckpointAge > 30*24*time.Hour || policy.ClockRollbackTolerance < 0 || policy.ClockRollbackTolerance > 5*time.Minute || policy.MaximumEntries == 0 || policy.MaximumEntries > audit.MaxJSONSafeSequence || policy.MaximumDatabaseBytes < 1<<20 {
		return audit.ErrUnavailable
	}
	if err := l.Verify(ctx); err != nil {
		return audit.ErrUnavailable
	}
	effectiveNow, err := l.observeOperationalClock(ctx, now, policy.ClockRollbackTolerance)
	if err != nil {
		return err
	}
	var entries, pageCount, pageSize uint64
	if err := l.db.QueryRowContext(ctx, `SELECT last_sequence FROM audit_metadata WHERE singleton = 1`).Scan(&entries); err != nil || entries >= policy.MaximumEntries || l.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pageCount) != nil || l.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&pageSize) != nil || pageSize == 0 || pageCount > policy.MaximumDatabaseBytes/pageSize {
		return audit.ErrUnavailable
	}
	signed, trust, err := l.LatestCheckpoint(ctx, authority)
	if err != nil || trust != audit.CheckpointTrusted || signed.Checkpoint.IssuedAt.After(effectiveNow) || effectiveNow.Sub(signed.Checkpoint.IssuedAt) > policy.MaximumCheckpointAge {
		return audit.ErrUnavailable
	}
	selection, err := signer.Select(ctx)
	if err != nil || selection.Algorithm != audit.CheckpointAlgorithm {
		return audit.ErrUnavailable
	}
	key, err := l.latestKey(ctx, selection.KeyID, authority)
	if err != nil || !audit.KeyTrustedAt(key.Statement, effectiveNow) || probe.CheckSigner(ctx, selection) != nil {
		return audit.ErrUnavailable
	}
	if policy.RequireWitness && l.verifyCheckpointWitnesses(ctx, signed.Reference, witnessVerifier) != nil {
		return audit.ErrUnavailable
	}
	return nil
}

func (l *Ledger) fenceRestored(ctx context.Context, digest audit.Hash) error {
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer tx.rollback()
	var fence string
	var existing []byte
	if err := tx.conn.QueryRowContext(ctx, `SELECT fence_state, restore_backup_digest FROM audit_operational_state WHERE singleton = 1`).Scan(&fence, &existing); err != nil {
		return audit.ErrUnavailable
	}
	if fence == "restore_fenced" {
		if !bytes.Equal(existing, digest[:]) {
			return audit.ErrUnavailable
		}
		return nil
	}
	if fence != "admitted" {
		return audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, `UPDATE audit_operational_state SET fence_state = 'restore_fenced', restore_backup_digest = ?, accepted_manifest_reference = NULL, external_checkpoint_reference = NULL, completion_receipt = NULL WHERE singleton = 1`, digest[:]); err != nil {
		return audit.ErrUnavailable
	}
	return tx.commit(ctx)
}

func (l *Ledger) observeOperationalClock(ctx context.Context, now time.Time, tolerance time.Duration) (time.Time, error) {
	nowMS := now.UnixMilli()
	if nowMS < 0 || uint64(nowMS) > audit.MaxJSONSafeSequence {
		return time.Time{}, audit.ErrUnavailable
	}
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return time.Time{}, audit.ErrUnavailable
	}
	defer tx.rollback()
	var fence string
	var high int64
	if err := tx.conn.QueryRowContext(ctx, `SELECT fence_state, wall_high_water_ms FROM audit_operational_state WHERE singleton = 1`).Scan(&fence, &high); err != nil || fence != "admitted" {
		return time.Time{}, audit.ErrUnavailable
	}
	if nowMS < high-tolerance.Milliseconds() {
		_, _ = tx.conn.ExecContext(ctx, `UPDATE audit_operational_state SET fence_state = 'clock_fenced' WHERE singleton = 1`)
		_ = tx.commit(ctx)
		return time.Time{}, audit.ErrUnavailable
	}
	if nowMS < high {
		nowMS = high
	}
	if _, err := tx.conn.ExecContext(ctx, `UPDATE audit_operational_state SET wall_high_water_ms = ? WHERE singleton = 1`, nowMS); err != nil || tx.commit(ctx) != nil {
		return time.Time{}, audit.ErrUnavailable
	}
	return time.UnixMilli(nowMS).UTC(), nil
}

func (l *Ledger) verifyCheckpointWitnesses(ctx context.Context, reference string, verifier audit.WitnessVerifier) error {
	if verifier == nil {
		return audit.ErrUnavailable
	}
	rows, err := l.db.QueryContext(ctx, `SELECT witness_id, canonical_acknowledgement FROM audit_witness_acknowledgements WHERE checkpoint_reference = ? ORDER BY witness_id`, reference)
	if err != nil {
		return audit.ErrUnavailable
	}
	acks := make([]audit.WitnessAcknowledgement, 0)
	for rows.Next() {
		var ack audit.WitnessAcknowledgement
		ack.CheckpointReference = reference
		if rows.Scan(&ack.WitnessID, &ack.Canonical) != nil {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		acks = append(acks, ack)
	}
	if rows.Err() != nil || rows.Close() != nil || len(acks) == 0 {
		return audit.ErrUnavailable
	}
	for _, ack := range acks {
		if audit.ValidateWitnessAcknowledgement(ack) == nil && verifier.VerifyWitness(ctx, ack) == nil {
			return nil
		}
	}
	return audit.ErrUnavailable
}

func requireAdmitted(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) error {
	var fence string
	if err := query.QueryRowContext(ctx, `SELECT fence_state FROM audit_operational_state WHERE singleton = 1`).Scan(&fence); err != nil || fence != "admitted" {
		return audit.ErrUnavailable
	}
	return nil
}

func verifyRecoveryState(ctx context.Context, db *sql.DB) error {
	var fence string
	var high uint64
	var restoreDigest []byte
	var acceptedManifest, externalCheckpoint, completionReceipt sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT fence_state, wall_high_water_ms, restore_backup_digest, accepted_manifest_reference, external_checkpoint_reference, completion_receipt FROM audit_operational_state WHERE singleton = 1`).Scan(&fence, &high, &restoreDigest, &acceptedManifest, &externalCheckpoint, &completionReceipt); err != nil || high > audit.MaxJSONSafeSequence {
		return audit.ErrUnavailable
	}
	if fence == "restore_fenced" {
		if len(restoreDigest) != sha256.Size || acceptedManifest.Valid || externalCheckpoint.Valid || completionReceipt.Valid {
			return audit.ErrUnavailable
		}
	} else if fence != "admitted" && fence != "clock_fenced" {
		return audit.ErrUnavailable
	}
	type storedManifest struct {
		reference, manifestID, checkpointReference, receipt string
		canonical, signature                                []byte
	}
	rows, err := db.QueryContext(ctx, `SELECT manifest_reference, manifest_id, canonical_manifest, signature, checkpoint_reference, completion_receipt FROM audit_recovery_manifests ORDER BY rowid`)
	if err != nil {
		return audit.ErrUnavailable
	}
	stored := make([]storedManifest, 0)
	for rows.Next() {
		var item storedManifest
		if rows.Scan(&item.reference, &item.manifestID, &item.canonical, &item.signature, &item.checkpointReference, &item.receipt) != nil {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		stored = append(stored, item)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return audit.ErrUnavailable
	}
	var authorityRaw []byte
	if len(stored) > 0 {
		if err := db.QueryRowContext(ctx, `SELECT public_key FROM audit_checkpoint_authority WHERE singleton = 1`).Scan(&authorityRaw); err != nil || len(authorityRaw) != ed25519.PublicKeySize {
			return audit.ErrUnavailable
		}
	}
	for _, item := range stored {
		if !recoveryReceiptPattern.MatchString(item.receipt) {
			return audit.ErrUnavailable
		}
		manifest, err := audit.ParseCanonicalRecoveryManifest(item.canonical)
		if err != nil || manifest.ManifestID != item.manifestID || manifest.CheckpointReference != item.checkpointReference {
			return audit.ErrUnavailable
		}
		reference, err := audit.RecoveryManifestReference(item.canonical, item.signature)
		if err != nil || reference != item.reference {
			return audit.ErrUnavailable
		}
		manifestKey, err := latestKeyFromDB(ctx, db, manifest.KeyID, ed25519.PublicKey(authorityRaw))
		if err != nil {
			return audit.ErrUnavailable
		}
		checkpoint, checkpointVersion, err := readCheckpoint(ctx, db, manifest.CheckpointReference)
		if err != nil {
			return audit.ErrUnavailable
		}
		checkpointKey, err := latestKeyFromDB(ctx, db, checkpoint.Checkpoint.KeyID, ed25519.PublicKey(authorityRaw))
		if err != nil || checkpointKey.Statement.Version < checkpointVersion {
			return audit.ErrUnavailable
		}
		signed := audit.SignedRecoveryManifest{Manifest: manifest, Canonical: item.canonical, Signature: item.signature, Reference: item.reference}
		if audit.VerifySignedRecoveryManifest(signed, manifestKey.Statement, checkpoint, checkpointKey.Statement) != nil {
			return audit.ErrUnavailable
		}
	}
	if acceptedManifest.Valid {
		if len(stored) == 0 || len(restoreDigest) != sha256.Size {
			return audit.ErrUnavailable
		}
		latest := stored[len(stored)-1]
		if latest.reference != acceptedManifest.String || latest.checkpointReference != externalCheckpoint.String || latest.receipt != completionReceipt.String {
			return audit.ErrUnavailable
		}
	} else if externalCheckpoint.Valid || completionReceipt.Valid || (fence != "restore_fenced" && (len(restoreDigest) != 0 || len(stored) != 0)) {
		return audit.ErrUnavailable
	}
	return nil
}

func latestKeyFromDB(ctx context.Context, db *sql.DB, keyID string, authority ed25519.PublicKey) (audit.SignedVerificationKeyStatement, error) {
	var canonical, signature []byte
	if err := db.QueryRowContext(ctx, `SELECT canonical_statement, authority_signature FROM audit_verification_key_statements WHERE key_id = ? ORDER BY version DESC LIMIT 1`, keyID).Scan(&canonical, &signature); err != nil {
		return audit.SignedVerificationKeyStatement{}, audit.ErrUnavailable
	}
	statement, err := audit.VerifyKeyStatement(authority, canonical, signature)
	if err != nil {
		return audit.SignedVerificationKeyStatement{}, err
	}
	return audit.SignedVerificationKeyStatement{Statement: statement, Canonical: canonical, Signature: signature}, nil
}
