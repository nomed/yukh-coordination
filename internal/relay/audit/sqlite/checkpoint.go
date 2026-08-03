package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func (l *Ledger) InstallVerificationKey(ctx context.Context, signed audit.SignedVerificationKeyStatement, authority ed25519.PublicKey, operationID string, recordedAt time.Time, authorityReference string) error {
	if l == nil || l.db == nil || ctx == nil {
		return audit.ErrUnavailable
	}
	statement, err := audit.VerifyKeyStatement(authority, signed.Canonical, signed.Signature)
	if err != nil {
		return audit.ErrUnavailable
	}
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer tx.rollback()
	if err := requireAdmitted(ctx, tx.conn); err != nil {
		return err
	}
	if err := pinAuthority(ctx, tx.conn, authority); err != nil {
		return err
	}
	record := identity.AuditRecord{ProfileVersion: 1, OperationID: operationID, Operation: identity.AuditKeyLifecycle, Outcome: identity.AuditAllow, Reason: identity.AuditReasonKeyLifecycleCommitted, DecisionTime: recordedAt, AuthorityReference: authorityReference, SigningKeyReference: fmt.Sprintf("signing-key:%s:%d", statement.KeyID, statement.Version)}
	canonicalRecord, err := audit.CanonicalRecord(record)
	if err != nil {
		return err
	}
	var previousVersion uint64
	var previousCanonical []byte
	err = tx.conn.QueryRowContext(ctx, `SELECT version, canonical_statement FROM audit_verification_key_statements WHERE key_id = ? ORDER BY version DESC LIMIT 1`, statement.KeyID).Scan(&previousVersion, &previousCanonical)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return audit.ErrUnavailable
	}
	if err == nil {
		if statement.Version == previousVersion {
			var previousSignature []byte
			if err := tx.conn.QueryRowContext(ctx, `SELECT authority_signature FROM audit_verification_key_statements WHERE key_id = ? AND version = ?`, statement.KeyID, statement.Version).Scan(&previousSignature); err != nil || !bytes.Equal(previousCanonical, signed.Canonical) || !bytes.Equal(previousSignature, signed.Signature) {
				return audit.ErrConflict
			}
			var existingCoverage []byte
			if err := tx.conn.QueryRowContext(ctx, `SELECT canonical_record FROM audit_entries WHERE json_extract(CAST(canonical_record AS TEXT), '$.operation_kind') = 'audit_key_lifecycle' AND json_extract(CAST(canonical_record AS TEXT), '$.signing_key_reference') = ?`, record.SigningKeyReference).Scan(&existingCoverage); err != nil || !bytes.Equal(existingCoverage, canonicalRecord) {
				return audit.ErrConflict
			}
			if _, err := appendRecord(ctx, tx.conn, record, canonicalRecord); err != nil {
				return err
			}
			return tx.commit(ctx)
		}
		if statement.Version < previousVersion {
			return audit.ErrConflict
		}
		previous, parseErr := audit.ParseCanonicalVerificationKeyStatement(previousCanonical)
		if parseErr != nil || !bytes.Equal(previous.PublicKey, statement.PublicKey) || statement.ActiveFrom != previous.ActiveFrom || statement.IssuedAt.Before(previous.IssuedAt) {
			return audit.ErrUnavailable
		}
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO audit_verification_key_statements (key_id, version, canonical_statement, authority_signature) VALUES (?, ?, ?, ?)`, statement.KeyID, statement.Version, signed.Canonical, signed.Signature); err != nil {
		return audit.ErrUnavailable
	}
	if _, err := appendRecord(ctx, tx.conn, record, canonicalRecord); err != nil {
		return err
	}
	if err := tx.commit(ctx); err != nil {
		return audit.ErrUnavailable
	}
	return nil
}

func (l *Ledger) CreateCheckpoint(ctx context.Context, issuedAt time.Time, authority ed25519.PublicKey, signer audit.CheckpointSigner, operationID string) (audit.SignedCheckpoint, error) {
	if l == nil || l.db == nil || ctx == nil || signer == nil {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	selection, err := signer.Select(ctx)
	if err != nil || selection.Algorithm != audit.CheckpointAlgorithm {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	key, err := l.latestKey(ctx, selection.KeyID, authority)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	record := identity.AuditRecord{ProfileVersion: 1, OperationID: operationID, Operation: identity.AuditCheckpoint, Outcome: identity.AuditAllow, Reason: identity.AuditReasonCheckpointCommitted, DecisionTime: issuedAt, SigningKeyReference: fmt.Sprintf("signing-key:%s:%d", selection.KeyID, key.Statement.Version)}
	canonicalRecord, err := audit.CanonicalRecord(record)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	checkpoint, err := l.checkpointCandidate(ctx, issuedAt, selection, record, canonicalRecord)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	canonical, err := audit.CanonicalCheckpoint(checkpoint)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	preimage, _ := audit.CheckpointPreimage(canonical)
	signature, err := signer.Sign(ctx, selection, preimage)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	reference, err := audit.CheckpointReference(canonical, signature)
	if err != nil {
		return audit.SignedCheckpoint{}, err
	}
	signed := audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: canonical, Signature: append([]byte(nil), signature...), Reference: reference}
	trust, err := audit.VerifySignedCheckpoint(signed, key.Statement)
	if err != nil || trust != audit.CheckpointTrusted {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	return l.commitCheckpoint(ctx, signed, key.Statement.Version, record, canonicalRecord)
}

func (l *Ledger) LatestCheckpoint(ctx context.Context, authority ed25519.PublicKey) (audit.SignedCheckpoint, audit.CheckpointTrust, error) {
	if l == nil || l.db == nil || ctx == nil {
		return audit.SignedCheckpoint{}, "", audit.ErrUnavailable
	}
	signed, keyVersion, err := readLatestCheckpoint(ctx, l.db)
	if err != nil {
		return audit.SignedCheckpoint{}, "", err
	}
	key, err := l.latestKey(ctx, signed.Checkpoint.KeyID, authority)
	if err != nil || key.Statement.Version < keyVersion {
		return audit.SignedCheckpoint{}, "", audit.ErrUnavailable
	}
	trust, err := audit.VerifySignedCheckpoint(signed, key.Statement)
	if err != nil {
		return audit.SignedCheckpoint{}, "", err
	}
	return signed, trust, nil
}

func (l *Ledger) ExportCheckpoint(ctx context.Context, reference string, authority ed25519.PublicKey) ([]byte, error) {
	if l == nil || l.db == nil || ctx == nil {
		return nil, audit.ErrUnavailable
	}
	signed, keyVersion, err := readCheckpoint(ctx, l.db, reference)
	if err != nil {
		return nil, err
	}
	key, err := l.latestKey(ctx, signed.Checkpoint.KeyID, authority)
	if err != nil || key.Statement.Version < keyVersion {
		return nil, audit.ErrUnavailable
	}
	if _, err := audit.VerifySignedCheckpoint(signed, key.Statement); err != nil {
		return nil, err
	}
	return audit.CanonicalCheckpointExport(signed, key)
}

func (l *Ledger) WitnessCheckpoint(ctx context.Context, reference string, authority ed25519.PublicKey, witness audit.CheckpointWitness, verifier audit.WitnessVerifier) (audit.WitnessAcknowledgement, error) {
	if witness == nil || verifier == nil {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	signed, keyVersion, err := readCheckpoint(ctx, l.db, reference)
	if err != nil {
		return audit.WitnessAcknowledgement{}, err
	}
	key, err := l.latestKey(ctx, signed.Checkpoint.KeyID, authority)
	if err != nil || key.Statement.Version < keyVersion {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	trust, err := audit.VerifySignedCheckpoint(signed, key.Statement)
	if err != nil || trust != audit.CheckpointTrusted {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	exported, err := l.ExportCheckpoint(ctx, reference, authority)
	if err != nil {
		return audit.WitnessAcknowledgement{}, err
	}
	ack, err := witness.Witness(ctx, exported)
	if err != nil || ack.CheckpointReference != reference || audit.ValidateWitnessAcknowledgement(ack) != nil || verifier.VerifyWitness(ctx, ack) != nil {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	digest := sha256.Sum256(ack.Canonical)
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	defer tx.rollback()
	if err := requireAdmitted(ctx, tx.conn); err != nil {
		return audit.WitnessAcknowledgement{}, err
	}
	var existing, existingDigest []byte
	err = tx.conn.QueryRowContext(ctx, `SELECT canonical_acknowledgement, acknowledgement_digest FROM audit_witness_acknowledgements WHERE witness_id = ? AND checkpoint_reference = ?`, ack.WitnessID, reference).Scan(&existing, &existingDigest)
	if err == nil {
		if !bytes.Equal(existing, ack.Canonical) || !bytes.Equal(existingDigest, digest[:]) {
			return audit.WitnessAcknowledgement{}, audit.ErrConflict
		}
		return ack, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO audit_witness_acknowledgements (witness_id, checkpoint_reference, canonical_acknowledgement, acknowledgement_digest) VALUES (?, ?, ?, ?)`, ack.WitnessID, reference, ack.Canonical, digest[:]); err != nil {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	if err := tx.commit(ctx); err != nil {
		return audit.WitnessAcknowledgement{}, audit.ErrUnavailable
	}
	return ack, nil
}

func (l *Ledger) checkpointCandidate(ctx context.Context, issuedAt time.Time, selection audit.CheckpointSigningSelection, record identity.AuditRecord, canonicalRecord []byte) (audit.Checkpoint, error) {
	if existing, found, err := lookupOperation(ctx, l.db, record.OperationID); err != nil {
		return audit.Checkpoint{}, audit.ErrUnavailable
	} else if found {
		if !bytes.Equal(existing.record, canonicalRecord) {
			return audit.Checkpoint{}, audit.ErrConflict
		}
		signed, _, err := readCheckpointAtSize(ctx, l.db, existing.receipt.Sequence)
		if err != nil || signed.Checkpoint.IssuedAt != issuedAt || signed.Checkpoint.KeyID != selection.KeyID || signed.Checkpoint.Algorithm != selection.Algorithm {
			return audit.Checkpoint{}, audit.ErrUnavailable
		}
		return signed.Checkpoint, nil
	}
	var ledgerID string
	var size uint64
	var root, head []byte
	if err := l.db.QueryRowContext(ctx, `SELECT ledger_id, merkle_size, merkle_root, chain_head FROM audit_metadata WHERE singleton = 1`).Scan(&ledgerID, &size, &root, &head); err != nil || len(root) != sha256.Size || len(head) != sha256.Size || size >= audit.MaxJSONSafeSequence {
		return audit.Checkpoint{}, audit.ErrUnavailable
	}
	var predecessor string
	var predecessorTime string
	err := l.db.QueryRowContext(ctx, `SELECT checkpoint_reference, json_extract(CAST(canonical_checkpoint AS TEXT), '$.issued_at') FROM audit_checkpoints ORDER BY tree_size DESC LIMIT 1`).Scan(&predecessor, &predecessorTime)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return audit.Checkpoint{}, audit.ErrUnavailable
	}
	if err == nil {
		parsed, parseErr := time.Parse("2006-01-02T15:04:05.000Z", predecessorTime)
		if parseErr != nil || issuedAt.Before(parsed) {
			return audit.Checkpoint{}, audit.ErrUnavailable
		}
	}
	leaves := make([]audit.Hash, 0, size+1)
	rows, err := l.db.QueryContext(ctx, `SELECT sequence, chain_digest FROM audit_entries ORDER BY sequence`)
	if err != nil {
		return audit.Checkpoint{}, audit.ErrUnavailable
	}
	for rows.Next() {
		var sequence uint64
		var digest []byte
		if rows.Scan(&sequence, &digest) != nil || sequence != uint64(len(leaves))+1 || len(digest) != sha256.Size {
			_ = rows.Close()
			return audit.Checkpoint{}, audit.ErrUnavailable
		}
		var chain audit.Hash
		copy(chain[:], digest)
		leaf, err := audit.MerkleLeafHash(sequence, chain)
		if err != nil {
			_ = rows.Close()
			return audit.Checkpoint{}, audit.ErrUnavailable
		}
		leaves = append(leaves, leaf)
	}
	if rows.Err() != nil || rows.Close() != nil || uint64(len(leaves)) != size {
		return audit.Checkpoint{}, audit.ErrUnavailable
	}
	var previous audit.Hash
	copy(previous[:], head)
	recordDigest := audit.RecordDigest(canonicalRecord)
	chainHead, err := audit.ChainDigest(size+1, previous, recordDigest)
	if err != nil {
		return audit.Checkpoint{}, err
	}
	leaf, err := audit.MerkleLeafHash(size+1, chainHead)
	if err != nil {
		return audit.Checkpoint{}, err
	}
	leaves = append(leaves, leaf)
	return audit.Checkpoint{LedgerID: ledgerID, TreeSize: size + 1, RootHash: audit.MerkleRoot(leaves), ChainHead: chainHead, IssuedAt: issuedAt, Algorithm: selection.Algorithm, KeyID: selection.KeyID, PredecessorReference: predecessor}, nil
}

func (l *Ledger) commitCheckpoint(ctx context.Context, signed audit.SignedCheckpoint, keyVersion uint64, record identity.AuditRecord, canonicalRecord []byte) (audit.SignedCheckpoint, error) {
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	defer tx.rollback()
	if err := requireAdmitted(ctx, tx.conn); err != nil {
		return audit.SignedCheckpoint{}, err
	}
	if _, err := appendRecord(ctx, tx.conn, record, canonicalRecord); err != nil {
		return audit.SignedCheckpoint{}, err
	}
	var ledgerID string
	var size uint64
	var root, head []byte
	if err := tx.conn.QueryRowContext(ctx, `SELECT ledger_id, merkle_size, merkle_root, chain_head FROM audit_metadata WHERE singleton = 1`).Scan(&ledgerID, &size, &root, &head); err != nil || ledgerID != signed.Checkpoint.LedgerID || size != signed.Checkpoint.TreeSize || !bytes.Equal(root, signed.Checkpoint.RootHash[:]) || !bytes.Equal(head, signed.Checkpoint.ChainHead[:]) {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	var latest string
	err = tx.conn.QueryRowContext(ctx, `SELECT checkpoint_reference FROM audit_checkpoints WHERE tree_size < ? ORDER BY tree_size DESC LIMIT 1`, signed.Checkpoint.TreeSize).Scan(&latest)
	if errors.Is(err, sql.ErrNoRows) {
		latest = ""
	} else if err != nil {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	if latest != signed.Checkpoint.PredecessorReference {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	var existingCanonical, existingSignature []byte
	var existingReference string
	err = tx.conn.QueryRowContext(ctx, `SELECT checkpoint_reference, canonical_checkpoint, signature FROM audit_checkpoints WHERE tree_size = ?`, size).Scan(&existingReference, &existingCanonical, &existingSignature)
	if err == nil {
		if existingReference != signed.Reference || !bytes.Equal(existingCanonical, signed.Canonical) || !bytes.Equal(existingSignature, signed.Signature) {
			return audit.SignedCheckpoint{}, audit.ErrConflict
		}
		return signed, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO audit_checkpoints (checkpoint_reference, tree_size, key_id, key_version, predecessor_reference, canonical_checkpoint, signature) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, signed.Reference, size, signed.Checkpoint.KeyID, keyVersion, signed.Checkpoint.PredecessorReference, signed.Canonical, signed.Signature); err != nil {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	if err := tx.commit(ctx); err != nil {
		return audit.SignedCheckpoint{}, audit.ErrUnavailable
	}
	return signed, nil
}

func (l *Ledger) latestKey(ctx context.Context, keyID string, authority ed25519.PublicKey) (audit.SignedVerificationKeyStatement, error) {
	if len(authority) != ed25519.PublicKeySize {
		return audit.SignedVerificationKeyStatement{}, audit.ErrUnavailable
	}
	var pinned []byte
	if err := l.db.QueryRowContext(ctx, `SELECT public_key FROM audit_checkpoint_authority WHERE singleton = 1`).Scan(&pinned); err != nil || !bytes.Equal(pinned, authority) {
		return audit.SignedVerificationKeyStatement{}, audit.ErrUnavailable
	}
	var canonical, signature []byte
	if err := l.db.QueryRowContext(ctx, `SELECT canonical_statement, authority_signature FROM audit_verification_key_statements WHERE key_id = ? ORDER BY version DESC LIMIT 1`, keyID).Scan(&canonical, &signature); err != nil {
		return audit.SignedVerificationKeyStatement{}, audit.ErrUnavailable
	}
	statement, err := audit.VerifyKeyStatement(authority, canonical, signature)
	if err != nil {
		return audit.SignedVerificationKeyStatement{}, err
	}
	return audit.SignedVerificationKeyStatement{Statement: statement, Canonical: canonical, Signature: signature}, nil
}

func pinAuthority(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, authority ed25519.PublicKey) error {
	if len(authority) != ed25519.PublicKeySize {
		return audit.ErrUnavailable
	}
	var existing []byte
	err := query.QueryRowContext(ctx, `SELECT public_key FROM audit_checkpoint_authority WHERE singleton = 1`).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, authority) {
			return audit.ErrConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return audit.ErrUnavailable
	}
	if _, err := query.ExecContext(ctx, `INSERT INTO audit_checkpoint_authority (singleton, public_key) VALUES (1, ?)`, []byte(authority)); err != nil {
		return audit.ErrUnavailable
	}
	return nil
}

func readLatestCheckpoint(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (audit.SignedCheckpoint, uint64, error) {
	return scanCheckpoint(query.QueryRowContext(ctx, `SELECT checkpoint_reference, key_version, canonical_checkpoint, signature FROM audit_checkpoints ORDER BY tree_size DESC LIMIT 1`))
}

func readCheckpoint(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, reference string) (audit.SignedCheckpoint, uint64, error) {
	return scanCheckpoint(query.QueryRowContext(ctx, `SELECT checkpoint_reference, key_version, canonical_checkpoint, signature FROM audit_checkpoints WHERE checkpoint_reference = ?`, reference))
}

func readCheckpointAtSize(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, size uint64) (audit.SignedCheckpoint, uint64, error) {
	return scanCheckpoint(query.QueryRowContext(ctx, `SELECT checkpoint_reference, key_version, canonical_checkpoint, signature FROM audit_checkpoints WHERE tree_size = ?`, size))
}

func scanCheckpoint(row *sql.Row) (audit.SignedCheckpoint, uint64, error) {
	var reference string
	var keyVersion uint64
	var canonical, signature []byte
	if err := row.Scan(&reference, &keyVersion, &canonical, &signature); err != nil {
		return audit.SignedCheckpoint{}, 0, audit.ErrUnavailable
	}
	checkpoint, err := audit.ParseCanonicalCheckpoint(canonical)
	if err != nil {
		return audit.SignedCheckpoint{}, 0, err
	}
	expected, err := audit.CheckpointReference(canonical, signature)
	if err != nil || expected != reference {
		return audit.SignedCheckpoint{}, 0, audit.ErrUnavailable
	}
	return audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: canonical, Signature: signature, Reference: reference}, keyVersion, nil
}

func verifyCheckpointState(ctx context.Context, db *sql.DB) error {
	var authorityRaw []byte
	err := db.QueryRowContext(ctx, `SELECT public_key FROM audit_checkpoint_authority WHERE singleton = 1`).Scan(&authorityRaw)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM audit_verification_key_statements) + (SELECT COUNT(*) FROM audit_checkpoints) + (SELECT COUNT(*) FROM audit_witness_acknowledgements)`).Scan(&count); err != nil || count != 0 {
			return audit.ErrUnavailable
		}
		return nil
	}
	if err != nil || len(authorityRaw) != ed25519.PublicKeySize {
		return audit.ErrUnavailable
	}
	authority := ed25519.PublicKey(authorityRaw)
	type keyCoordinate struct {
		id      string
		version uint64
	}
	keys := make(map[keyCoordinate]audit.VerificationKeyStatement)
	latest := make(map[string]audit.VerificationKeyStatement)
	keyReferences := make([]string, 0)
	rows, err := db.QueryContext(ctx, `SELECT key_id, version, canonical_statement, authority_signature FROM audit_verification_key_statements ORDER BY key_id, version`)
	if err != nil {
		return audit.ErrUnavailable
	}
	for rows.Next() {
		var keyID string
		var version uint64
		var canonical, signature []byte
		if rows.Scan(&keyID, &version, &canonical, &signature) != nil {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		statement, err := audit.VerifyKeyStatement(authority, canonical, signature)
		if err != nil || statement.KeyID != keyID || statement.Version != version {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		if previous, ok := latest[keyID]; ok && (version <= previous.Version || !bytes.Equal(statement.PublicKey, previous.PublicKey) || statement.ActiveFrom != previous.ActiveFrom || statement.IssuedAt.Before(previous.IssuedAt)) {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		keys[keyCoordinate{id: keyID, version: version}] = statement
		latest[keyID] = statement
		keyReferences = append(keyReferences, fmt.Sprintf("signing-key:%s:%d", keyID, version))
	}
	if rows.Err() != nil || rows.Close() != nil {
		return audit.ErrUnavailable
	}
	for _, keyReference := range keyReferences {
		var coverage int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_entries WHERE json_extract(CAST(canonical_record AS TEXT), '$.operation_kind') = 'audit_key_lifecycle' AND json_extract(CAST(canonical_record AS TEXT), '$.signing_key_reference') = ?`, keyReference).Scan(&coverage); err != nil || coverage != 1 {
			return audit.ErrUnavailable
		}
	}

	checkpointRows, err := db.QueryContext(ctx, `SELECT checkpoint_reference, tree_size, key_id, key_version, canonical_checkpoint, signature FROM audit_checkpoints ORDER BY tree_size`)
	if err != nil {
		return audit.ErrUnavailable
	}
	type storedCheckpoint struct {
		reference, keyID     string
		treeSize, keyVersion uint64
		canonical, signature []byte
	}
	storedCheckpoints := make([]storedCheckpoint, 0)
	for checkpointRows.Next() {
		var stored storedCheckpoint
		if checkpointRows.Scan(&stored.reference, &stored.treeSize, &stored.keyID, &stored.keyVersion, &stored.canonical, &stored.signature) != nil {
			_ = checkpointRows.Close()
			return audit.ErrUnavailable
		}
		storedCheckpoints = append(storedCheckpoints, stored)
	}
	if checkpointRows.Err() != nil || checkpointRows.Close() != nil {
		return audit.ErrUnavailable
	}
	var predecessor string
	var priorSize uint64
	for _, stored := range storedCheckpoints {
		var chainRaw, coverageRaw []byte
		if stored.treeSize <= priorSize {
			return audit.ErrUnavailable
		}
		checkpoint, err := audit.ParseCanonicalCheckpoint(stored.canonical)
		if err != nil || checkpoint.TreeSize != stored.treeSize || checkpoint.KeyID != stored.keyID || checkpoint.PredecessorReference != predecessor {
			return audit.ErrUnavailable
		}
		expectedReference, err := audit.CheckpointReference(stored.canonical, stored.signature)
		if err != nil || expectedReference != stored.reference {
			return audit.ErrUnavailable
		}
		root, err := subtreeHash(ctx, db, 0, stored.treeSize)
		if err != nil || root != checkpoint.RootHash || db.QueryRowContext(ctx, `SELECT chain_digest, canonical_record FROM audit_entries WHERE sequence = ?`, stored.treeSize).Scan(&chainRaw, &coverageRaw) != nil || len(chainRaw) != sha256.Size || !bytes.Equal(chainRaw, checkpoint.ChainHead[:]) || audit.ValidateCanonicalRecord(coverageRaw) != nil {
			return audit.ErrUnavailable
		}
		var coverage struct {
			OperationKind       string `json:"operation_kind"`
			DecisionTime        string `json:"decision_time"`
			SigningKeyReference string `json:"signing_key_reference"`
		}
		if json.Unmarshal(coverageRaw, &coverage) != nil || coverage.OperationKind != string(identity.AuditCheckpoint) || coverage.DecisionTime != checkpoint.IssuedAt.Format("2006-01-02T15:04:05.000Z") || coverage.SigningKeyReference != fmt.Sprintf("signing-key:%s:%d", checkpoint.KeyID, stored.keyVersion) {
			return audit.ErrUnavailable
		}
		statement, ok := keys[keyCoordinate{id: stored.keyID, version: stored.keyVersion}]
		if !ok {
			return audit.ErrUnavailable
		}
		signed := audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: stored.canonical, Signature: stored.signature, Reference: stored.reference}
		if _, err := audit.VerifySignedCheckpoint(signed, statement); err != nil {
			return audit.ErrUnavailable
		}
		if current, ok := latest[stored.keyID]; !ok {
			return audit.ErrUnavailable
		} else if _, err := audit.VerifySignedCheckpoint(signed, current); err != nil {
			return audit.ErrUnavailable
		}
		predecessor = stored.reference
		priorSize = stored.treeSize
	}

	witnessRows, err := db.QueryContext(ctx, `SELECT witness_id, checkpoint_reference, canonical_acknowledgement, acknowledgement_digest FROM audit_witness_acknowledgements`)
	if err != nil {
		return audit.ErrUnavailable
	}
	for witnessRows.Next() {
		var ack audit.WitnessAcknowledgement
		var digestRaw []byte
		if witnessRows.Scan(&ack.WitnessID, &ack.CheckpointReference, &ack.Canonical, &digestRaw) != nil || len(digestRaw) != sha256.Size || audit.ValidateWitnessAcknowledgement(ack) != nil {
			_ = witnessRows.Close()
			return audit.ErrUnavailable
		}
		digest := sha256.Sum256(ack.Canonical)
		if !bytes.Equal(digestRaw, digest[:]) {
			_ = witnessRows.Close()
			return audit.ErrUnavailable
		}
	}
	if witnessRows.Err() != nil || witnessRows.Close() != nil {
		return audit.ErrUnavailable
	}
	return nil
}
