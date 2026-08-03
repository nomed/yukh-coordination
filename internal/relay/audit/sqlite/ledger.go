// Package sqlite implements the RFC-0011 local security-audit ledger.
package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
	_ "modernc.org/sqlite"
)

const schemaVersion = 4

const metadataAppendTriggerV2 = `CREATE TRIGGER audit_metadata_append_only BEFORE UPDATE ON audit_metadata
	WHEN NEW.singleton != OLD.singleton OR NEW.profile_version != OLD.profile_version OR NEW.ledger_id != OLD.ledger_id
		OR NEW.last_sequence != OLD.last_sequence + 1 OR NEW.chain_head = OLD.chain_head
		OR NEW.merkle_size != OLD.merkle_size + 1 OR NEW.merkle_size != NEW.last_sequence OR NEW.merkle_root = OLD.merkle_root
	BEGIN SELECT RAISE(ABORT, 'audit metadata transition is invalid'); END`

const merkleNodesNoDeleteTrigger = `CREATE TRIGGER merkle_nodes_no_delete BEFORE DELETE ON merkle_nodes BEGIN SELECT RAISE(ABORT, 'merkle nodes are immutable'); END`
const merkleNodesNoUpdateTrigger = `CREATE TRIGGER merkle_nodes_no_update BEFORE UPDATE ON merkle_nodes BEGIN SELECT RAISE(ABORT, 'merkle nodes are immutable'); END`

type Ledger struct{ db *sql.DB }

func Open(path string) (*Ledger, error) {
	return open(path, true)
}

// OpenRestored verifies the immutable backup bytes before SQLite can modify
// them, then persists a restore fence before returning the ledger.
func OpenRestored(path string, expectedBackupDigest audit.Hash) (*Ledger, error) {
	digest, err := audit.DigestBackupFile(path)
	if err != nil || digest != expectedBackupDigest {
		return nil, audit.ErrUnavailable
	}
	ledger, err := open(path, false)
	if err != nil {
		return nil, err
	}
	if err := ledger.fenceRestored(context.Background(), expectedBackupDigest); err != nil {
		_ = ledger.Close()
		return nil, err
	}
	if err := ledger.Verify(context.Background()); err != nil {
		_ = ledger.Close()
		return nil, err
	}
	return ledger, nil
}

func open(path string, verify bool) (*Ledger, error) {
	if path == "" {
		return nil, audit.ErrUnavailable
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, audit.ErrUnavailable
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute, RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=wal&_synchronous=full"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, audit.ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ledger := &Ledger{db: db}
	if err := ledger.configure(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ledger.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if verify {
		if err := ledger.Verify(context.Background()); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return ledger, nil
}

func (l *Ledger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

func (l *Ledger) Record(ctx context.Context, record identity.AuditRecord) (string, error) {
	receipt, err := l.Append(ctx, record)
	if err != nil {
		return "", err
	}
	return receipt.Reference(), nil
}

func (l *Ledger) Ready(ctx context.Context) error { return l.Verify(ctx) }

func (l *Ledger) Append(ctx context.Context, record identity.AuditRecord) (audit.Receipt, error) {
	if l == nil || l.db == nil || ctx == nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	canonical, err := audit.CanonicalRecord(record)
	if err != nil {
		return audit.Receipt{}, err
	}
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	defer tx.rollback()
	if err := requireAdmitted(ctx, tx.conn); err != nil {
		return audit.Receipt{}, err
	}
	receipt, err := appendRecord(ctx, tx.conn, record, canonical)
	if err != nil {
		return audit.Receipt{}, err
	}
	if err := tx.commit(ctx); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	return receipt, nil
}

func appendRecord(ctx context.Context, conn *sql.Conn, record identity.AuditRecord, canonical []byte) (audit.Receipt, error) {
	if existing, found, err := lookupOperation(ctx, conn, record.OperationID); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	} else if found {
		if !bytes.Equal(existing.record, canonical) {
			return audit.Receipt{}, audit.ErrConflict
		}
		return existing.receipt, nil
	}

	var ledgerID string
	var lastSequence, merkleSize uint64
	var previousBytes, merkleRootBytes []byte
	if err := conn.QueryRowContext(ctx, "SELECT ledger_id, last_sequence, chain_head, merkle_size, merkle_root FROM audit_metadata WHERE singleton = 1").Scan(&ledgerID, &lastSequence, &previousBytes, &merkleSize, &merkleRootBytes); err != nil || len(previousBytes) != sha256.Size || len(merkleRootBytes) != sha256.Size || lastSequence >= audit.MaxJSONSafeSequence || merkleSize != lastSequence {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	if err := verifyHead(ctx, conn, ledgerID, lastSequence, previousBytes); err != nil {
		return audit.Receipt{}, err
	}
	if root, err := subtreeHash(ctx, conn, 0, merkleSize); err != nil || !bytes.Equal(root[:], merkleRootBytes) {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	sequence := lastSequence + 1
	var previous [sha256.Size]byte
	copy(previous[:], previousBytes)
	recordDigest := audit.RecordDigest(canonical)
	chainDigest, err := audit.ChainDigest(sequence, previous, recordDigest)
	if err != nil {
		return audit.Receipt{}, err
	}
	receipt, err := audit.NewReceipt(ledgerID, sequence, record.OperationID, recordDigest, previous, chainDigest)
	if err != nil {
		return audit.Receipt{}, err
	}
	canonicalReceipt, err := audit.CanonicalReceipt(receipt)
	if err != nil {
		return audit.Receipt{}, err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO audit_entries
		(sequence, operation_id, canonical_record, record_digest, previous_chain_digest, chain_digest, canonical_receipt)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sequence, record.OperationID, canonical, recordDigest[:], previous[:], chainDigest[:], canonicalReceipt); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	leafHash, err := audit.MerkleLeafHash(sequence, chainDigest)
	if err != nil || insertMerkleLeaf(ctx, conn, sequence-1, leafHash) != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	merkleRoot, err := subtreeHash(ctx, conn, 0, sequence)
	if err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	result, err := conn.ExecContext(ctx, `UPDATE audit_metadata SET last_sequence = ?, chain_head = ?, merkle_size = ?, merkle_root = ?
		WHERE singleton = 1 AND last_sequence = ? AND chain_head = ? AND merkle_size = ? AND merkle_root = ?`,
		sequence, chainDigest[:], sequence, merkleRoot[:], lastSequence, previous[:], merkleSize, merkleRootBytes)
	if err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	return receipt, nil
}

func (l *Ledger) Verify(ctx context.Context) error {
	if l == nil || l.db == nil || ctx == nil {
		return audit.ErrUnavailable
	}
	lastSequence, expectedNodes, err := verifiedChainState(ctx, l.db)
	if err != nil {
		return audit.ErrUnavailable
	}
	var merkleSize uint64
	var storedMerkleRoot []byte
	if err := l.db.QueryRowContext(ctx, "SELECT merkle_size, merkle_root FROM audit_metadata WHERE singleton = 1").Scan(&merkleSize, &storedMerkleRoot); err != nil || len(storedMerkleRoot) != sha256.Size || merkleSize != lastSequence {
		return audit.ErrUnavailable
	}
	expectedRoot := rootFromExpected(expectedNodes, lastSequence)
	if !bytes.Equal(storedMerkleRoot, expectedRoot[:]) {
		return audit.ErrUnavailable
	}
	if err := verifyStoredNodes(ctx, l.db, expectedNodes); err != nil {
		return err
	}
	if err := verifyCheckpointState(ctx, l.db); err != nil {
		return err
	}
	return verifyRecoveryState(ctx, l.db)
}

type chainReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func verifiedChainState(ctx context.Context, query chainReader) (uint64, map[nodeCoordinate]audit.Hash, error) {
	var ledgerID string
	var lastSequence uint64
	var head []byte
	if err := query.QueryRowContext(ctx, "SELECT ledger_id, last_sequence, chain_head FROM audit_metadata WHERE singleton = 1").Scan(&ledgerID, &lastSequence, &head); err != nil || len(head) != sha256.Size {
		return 0, nil, audit.ErrUnavailable
	}
	genesis, err := audit.GenesisDigest(ledgerID)
	if err != nil {
		return 0, nil, audit.ErrUnavailable
	}
	previous := genesis
	rows, err := query.QueryContext(ctx, `SELECT sequence, operation_id, canonical_record, record_digest, previous_chain_digest, chain_digest, canonical_receipt FROM audit_entries ORDER BY sequence`)
	if err != nil {
		return 0, nil, audit.ErrUnavailable
	}
	defer rows.Close()
	var count uint64
	expectedNodes := make(map[nodeCoordinate]audit.Hash)
	for rows.Next() {
		count++
		var sequence uint64
		var operationID string
		var canonical, recordBytes, previousBytes, chainBytes, receiptBytes []byte
		if err := rows.Scan(&sequence, &operationID, &canonical, &recordBytes, &previousBytes, &chainBytes, &receiptBytes); err != nil || sequence != count || len(recordBytes) != sha256.Size || len(previousBytes) != sha256.Size || len(chainBytes) != sha256.Size {
			return 0, nil, audit.ErrUnavailable
		}
		if err := audit.ValidateCanonicalRecord(canonical); err != nil {
			return 0, nil, audit.ErrUnavailable
		}
		recordDigest := audit.RecordDigest(canonical)
		if !bytes.Equal(recordBytes, recordDigest[:]) || !bytes.Equal(previousBytes, previous[:]) {
			return 0, nil, audit.ErrUnavailable
		}
		chainDigest, err := audit.ChainDigest(sequence, previous, recordDigest)
		if err != nil || !bytes.Equal(chainBytes, chainDigest[:]) {
			return 0, nil, audit.ErrUnavailable
		}
		receipt, err := audit.NewReceipt(ledgerID, sequence, operationID, recordDigest, previous, chainDigest)
		if err != nil {
			return 0, nil, audit.ErrUnavailable
		}
		expectedReceipt, err := audit.CanonicalReceipt(receipt)
		if err != nil || !bytes.Equal(receiptBytes, expectedReceipt) {
			return 0, nil, audit.ErrUnavailable
		}
		leafHash, err := audit.MerkleLeafHash(sequence, chainDigest)
		if err != nil {
			return 0, nil, audit.ErrUnavailable
		}
		addExpectedLeaf(expectedNodes, sequence-1, leafHash)
		previous = chainDigest
	}
	if rows.Err() != nil || rows.Close() != nil || count != lastSequence || !bytes.Equal(head, previous[:]) {
		return 0, nil, audit.ErrUnavailable
	}
	return count, expectedNodes, nil
}

func (l *Ledger) configure(ctx context.Context) error {
	var journal string
	if err := l.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return audit.ErrUnavailable
	}
	for _, statement := range []string{"PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := l.db.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	return nil
}

func (l *Ledger) migrate(ctx context.Context) error {
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer tx.rollback()
	var version int
	if err := tx.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version < 0 || version > schemaVersion {
		return audit.ErrUnavailable
	}
	if version == 0 {
		if err := migrateV1(ctx, tx.conn); err != nil {
			return audit.ErrUnavailable
		}
		version = 1
	}
	if version == 1 {
		if err := migrateV2(ctx, tx.conn); err != nil {
			return audit.ErrUnavailable
		}
		version = 2
	}
	if version == 2 {
		if err := migrateV3(ctx, tx.conn); err != nil {
			return audit.ErrUnavailable
		}
		version = 3
	}
	if version == 3 {
		if err := migrateV4(ctx, tx.conn); err != nil {
			return audit.ErrUnavailable
		}
		version = 4
	}
	if version != schemaVersion {
		return audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, "PRAGMA user_version=4"); err != nil {
		return audit.ErrUnavailable
	}
	return tx.commit(ctx)
}

func migrateV4(ctx context.Context, conn *sql.Conn) error {
	statements := []string{
		`CREATE TABLE audit_operational_state (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			fence_state TEXT NOT NULL CHECK (fence_state IN ('admitted', 'restore_fenced', 'clock_fenced')),
			wall_high_water_ms INTEGER NOT NULL CHECK (wall_high_water_ms >= 0 AND wall_high_water_ms <= 9007199254740991),
			restore_backup_digest BLOB CHECK (restore_backup_digest IS NULL OR length(restore_backup_digest) = 32),
			accepted_manifest_reference TEXT CHECK (accepted_manifest_reference IS NULL OR (length(accepted_manifest_reference) = 58 AND accepted_manifest_reference GLOB 'audit-recovery:*' AND accepted_manifest_reference NOT GLOB '*[^A-Za-z0-9_:-]*')),
			external_checkpoint_reference TEXT CHECK (external_checkpoint_reference IS NULL OR (length(external_checkpoint_reference) = 60 AND external_checkpoint_reference GLOB 'audit-checkpoint:*' AND external_checkpoint_reference NOT GLOB '*[^A-Za-z0-9_:-]*')),
			completion_receipt TEXT CHECK (completion_receipt IS NULL OR (length(completion_receipt) BETWEEN 1 AND 256 AND completion_receipt NOT GLOB '*[^A-Za-z0-9._:/-]*')),
			CHECK ((fence_state = 'restore_fenced' AND restore_backup_digest IS NOT NULL AND accepted_manifest_reference IS NULL AND external_checkpoint_reference IS NULL AND completion_receipt IS NULL) OR (fence_state != 'restore_fenced'))
		) STRICT`,
		`CREATE TABLE audit_recovery_manifests (
			manifest_reference TEXT PRIMARY KEY CHECK (length(manifest_reference) = 58 AND manifest_reference GLOB 'audit-recovery:*' AND manifest_reference NOT GLOB '*[^A-Za-z0-9_:-]*'),
			manifest_id TEXT NOT NULL UNIQUE CHECK (manifest_id GLOB '????????-????-7???-[89ab]???-????????????' AND manifest_id NOT GLOB '*[^0-9a-f-]*'),
			canonical_manifest BLOB NOT NULL UNIQUE CHECK (length(canonical_manifest) BETWEEN 1 AND 1048576),
			signature BLOB NOT NULL CHECK (length(signature) = 64),
			checkpoint_reference TEXT NOT NULL CHECK (length(checkpoint_reference) = 60),
			completion_receipt TEXT NOT NULL CHECK (length(completion_receipt) BETWEEN 1 AND 256 AND completion_receipt NOT GLOB '*[^A-Za-z0-9._:/-]*')
		) STRICT`,
		`INSERT INTO audit_operational_state VALUES (1, 'admitted', 0, NULL, NULL, NULL, NULL)`,
		`CREATE TRIGGER audit_operational_state_transition BEFORE UPDATE ON audit_operational_state
			WHEN NEW.singleton != OLD.singleton OR NEW.wall_high_water_ms < OLD.wall_high_water_ms OR NOT (
				(OLD.fence_state = 'admitted' AND NEW.fence_state = 'admitted' AND NEW.restore_backup_digest IS OLD.restore_backup_digest AND NEW.accepted_manifest_reference IS OLD.accepted_manifest_reference AND NEW.external_checkpoint_reference IS OLD.external_checkpoint_reference AND NEW.completion_receipt IS OLD.completion_receipt) OR
				(OLD.fence_state = 'admitted' AND NEW.fence_state = 'restore_fenced' AND NEW.restore_backup_digest IS NOT NULL AND NEW.accepted_manifest_reference IS NULL AND NEW.external_checkpoint_reference IS NULL AND NEW.completion_receipt IS NULL) OR
				(OLD.fence_state = 'admitted' AND NEW.fence_state = 'clock_fenced' AND NEW.restore_backup_digest IS OLD.restore_backup_digest AND NEW.accepted_manifest_reference IS OLD.accepted_manifest_reference AND NEW.external_checkpoint_reference IS OLD.external_checkpoint_reference AND NEW.completion_receipt IS OLD.completion_receipt) OR
				(OLD.fence_state = 'restore_fenced' AND NEW.fence_state = 'admitted' AND NEW.restore_backup_digest = OLD.restore_backup_digest AND NEW.accepted_manifest_reference IS NOT NULL AND NEW.external_checkpoint_reference IS NOT NULL AND NEW.completion_receipt IS NOT NULL)
			)
			BEGIN SELECT RAISE(ABORT, 'audit operational transition is invalid'); END`,
		`CREATE TRIGGER audit_operational_state_no_delete BEFORE DELETE ON audit_operational_state BEGIN SELECT RAISE(ABORT, 'audit operational state is immutable'); END`,
		`CREATE TRIGGER audit_recovery_manifests_no_update BEFORE UPDATE ON audit_recovery_manifests BEGIN SELECT RAISE(ABORT, 'recovery manifests are immutable'); END`,
		`CREATE TRIGGER audit_recovery_manifests_no_delete BEFORE DELETE ON audit_recovery_manifests BEGIN SELECT RAISE(ABORT, 'recovery manifests are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	return nil
}

func migrateV3(ctx context.Context, conn *sql.Conn) error {
	statements := []string{
		`CREATE TABLE audit_verification_key_statements (
			key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128 AND key_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
			version INTEGER NOT NULL CHECK (version > 0 AND version <= 9007199254740991),
			canonical_statement BLOB NOT NULL CHECK (length(canonical_statement) BETWEEN 1 AND 4096),
			authority_signature BLOB NOT NULL CHECK (length(authority_signature) = 64),
			PRIMARY KEY (key_id, version),
			UNIQUE (canonical_statement)
		) STRICT`,
		`CREATE TABLE audit_checkpoint_authority (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			public_key BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32)
		) STRICT`,
		`CREATE TABLE audit_checkpoints (
			checkpoint_reference TEXT PRIMARY KEY CHECK (length(checkpoint_reference) = 60 AND checkpoint_reference GLOB 'audit-checkpoint:*' AND checkpoint_reference NOT GLOB '*[^A-Za-z0-9_:-]*'),
			tree_size INTEGER NOT NULL UNIQUE CHECK (tree_size > 0 AND tree_size <= 9007199254740991),
			key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128 AND key_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
			key_version INTEGER NOT NULL CHECK (key_version > 0 AND key_version <= 9007199254740991),
			predecessor_reference TEXT UNIQUE,
			canonical_checkpoint BLOB NOT NULL UNIQUE CHECK (length(canonical_checkpoint) BETWEEN 1 AND 4096),
			signature BLOB NOT NULL CHECK (length(signature) = 64),
			FOREIGN KEY (key_id, key_version) REFERENCES audit_verification_key_statements(key_id, version)
		) STRICT`,
		`CREATE TABLE audit_witness_acknowledgements (
			witness_id TEXT NOT NULL CHECK (length(witness_id) BETWEEN 1 AND 128 AND witness_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
			checkpoint_reference TEXT NOT NULL,
			canonical_acknowledgement BLOB NOT NULL CHECK (length(canonical_acknowledgement) BETWEEN 1 AND 16384),
			acknowledgement_digest BLOB NOT NULL UNIQUE CHECK (length(acknowledgement_digest) = 32),
			PRIMARY KEY (witness_id, checkpoint_reference),
			FOREIGN KEY (checkpoint_reference) REFERENCES audit_checkpoints(checkpoint_reference)
		) STRICT`,
		`CREATE TRIGGER audit_verification_keys_no_update BEFORE UPDATE ON audit_verification_key_statements BEGIN SELECT RAISE(ABORT, 'verification key statements are immutable'); END`,
		`CREATE TRIGGER audit_verification_keys_no_delete BEFORE DELETE ON audit_verification_key_statements BEGIN SELECT RAISE(ABORT, 'verification key statements are immutable'); END`,
		`CREATE TRIGGER audit_checkpoint_authority_no_update BEFORE UPDATE ON audit_checkpoint_authority BEGIN SELECT RAISE(ABORT, 'checkpoint authority is immutable'); END`,
		`CREATE TRIGGER audit_checkpoint_authority_no_delete BEFORE DELETE ON audit_checkpoint_authority BEGIN SELECT RAISE(ABORT, 'checkpoint authority is immutable'); END`,
		`CREATE TRIGGER audit_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints BEGIN SELECT RAISE(ABORT, 'audit checkpoints are immutable'); END`,
		`CREATE TRIGGER audit_checkpoints_no_delete BEFORE DELETE ON audit_checkpoints BEGIN SELECT RAISE(ABORT, 'audit checkpoints are immutable'); END`,
		`CREATE TRIGGER audit_witnesses_no_update BEFORE UPDATE ON audit_witness_acknowledgements BEGIN SELECT RAISE(ABORT, 'witness acknowledgements are immutable'); END`,
		`CREATE TRIGGER audit_witnesses_no_delete BEFORE DELETE ON audit_witness_acknowledgements BEGIN SELECT RAISE(ABORT, 'witness acknowledgements are immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	return nil
}

func migrateV1(ctx context.Context, conn *sql.Conn) error {
	statements := []string{
		`CREATE TABLE audit_metadata (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			profile_version INTEGER NOT NULL CHECK (profile_version = 1),
			ledger_id TEXT NOT NULL UNIQUE CHECK (ledger_id GLOB '????????-????-7???-[89ab]???-????????????' AND ledger_id NOT GLOB '*[^0-9a-f-]*'),
			last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0 AND last_sequence <= 9007199254740991),
			chain_head BLOB NOT NULL CHECK (length(chain_head) = 32)
		) STRICT`,
		`CREATE TABLE audit_entries (
			sequence INTEGER PRIMARY KEY CHECK (sequence > 0 AND sequence <= 9007199254740991),
			operation_id TEXT NOT NULL UNIQUE CHECK (operation_id GLOB '????????-????-7???-[89ab]???-????????????' AND operation_id NOT GLOB '*[^0-9a-f-]*'),
			canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 4096),
			record_digest BLOB NOT NULL UNIQUE CHECK (length(record_digest) = 32),
			previous_chain_digest BLOB NOT NULL CHECK (length(previous_chain_digest) = 32),
			chain_digest BLOB NOT NULL UNIQUE CHECK (length(chain_digest) = 32),
			canonical_receipt BLOB NOT NULL CHECK (length(canonical_receipt) BETWEEN 1 AND 2048)
		) STRICT`,
		`CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are immutable'); END`,
		`CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries BEGIN SELECT RAISE(ABORT, 'audit entries are immutable'); END`,
		`CREATE TRIGGER audit_metadata_append_only BEFORE UPDATE ON audit_metadata
			WHEN NEW.singleton != OLD.singleton OR NEW.profile_version != OLD.profile_version OR NEW.ledger_id != OLD.ledger_id
				OR NEW.last_sequence != OLD.last_sequence + 1 OR NEW.chain_head = OLD.chain_head
			BEGIN SELECT RAISE(ABORT, 'audit metadata transition is invalid'); END`,
		`CREATE TRIGGER audit_metadata_no_delete BEFORE DELETE ON audit_metadata BEGIN SELECT RAISE(ABORT, 'audit metadata is immutable'); END`,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	ledgerID, err := uuid.NewV7()
	if err != nil {
		return audit.ErrUnavailable
	}
	genesis, err := audit.GenesisDigest(ledgerID.String())
	if err != nil {
		return audit.ErrUnavailable
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO audit_metadata VALUES (1, 1, ?, 0, ?)", ledgerID.String(), genesis[:]); err != nil {
		return audit.ErrUnavailable
	}
	return nil
}

func migrateV2(ctx context.Context, conn *sql.Conn) error {
	emptyRoot := audit.EmptyMerkleRoot()
	statements := []string{
		`DROP TRIGGER audit_metadata_append_only`,
		`DROP TRIGGER audit_metadata_no_delete`,
		`ALTER TABLE audit_metadata ADD COLUMN merkle_size INTEGER NOT NULL DEFAULT 0 CHECK (merkle_size >= 0 AND merkle_size <= 9007199254740991)`,
		`ALTER TABLE audit_metadata ADD COLUMN merkle_root BLOB NOT NULL DEFAULT X'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855' CHECK (length(merkle_root) = 32)`,
		`CREATE TABLE merkle_nodes (
			level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 52),
			node_index INTEGER NOT NULL CHECK (node_index >= 0 AND node_index <= 9007199254740991),
			node_hash BLOB NOT NULL UNIQUE CHECK (length(node_hash) = 32),
			PRIMARY KEY (level, node_index)
		) STRICT`,
		merkleNodesNoUpdateTrigger,
		merkleNodesNoDeleteTrigger,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	rows, err := conn.QueryContext(ctx, "SELECT sequence, chain_digest FROM audit_entries ORDER BY sequence")
	if err != nil {
		return audit.ErrUnavailable
	}
	var size uint64
	for rows.Next() {
		var sequence uint64
		var chainBytes []byte
		if err := rows.Scan(&sequence, &chainBytes); err != nil || sequence != size+1 || len(chainBytes) != sha256.Size {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		var chainDigest [sha256.Size]byte
		copy(chainDigest[:], chainBytes)
		leafHash, err := audit.MerkleLeafHash(sequence, chainDigest)
		if err != nil || insertMerkleLeaf(ctx, conn, size, leafHash) != nil {
			_ = rows.Close()
			return audit.ErrUnavailable
		}
		size++
	}
	if rows.Err() != nil || rows.Close() != nil {
		return audit.ErrUnavailable
	}
	root := emptyRoot
	if size > 0 {
		root, err = subtreeHash(ctx, conn, 0, size)
		if err != nil {
			return audit.ErrUnavailable
		}
	}
	if _, err := conn.ExecContext(ctx, "UPDATE audit_metadata SET merkle_size = ?, merkle_root = ? WHERE singleton = 1", size, root[:]); err != nil {
		return audit.ErrUnavailable
	}
	for _, statement := range []string{
		metadataAppendTriggerV2,
		`CREATE TRIGGER audit_metadata_no_delete BEFORE DELETE ON audit_metadata BEGIN SELECT RAISE(ABORT, 'audit metadata is immutable'); END`,
	} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	return nil
}

type storedOperation struct {
	record  []byte
	receipt audit.Receipt
}

func lookupOperation(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, operationID string) (storedOperation, bool, error) {
	var stored storedOperation
	var sequence uint64
	var ledgerID string
	var recordDigest, previousDigest, chainDigest []byte
	err := query.QueryRowContext(ctx, `SELECT e.sequence, m.ledger_id, e.canonical_record, e.record_digest, e.previous_chain_digest, e.chain_digest
		FROM audit_entries e CROSS JOIN audit_metadata m WHERE e.operation_id = ? AND m.singleton = 1`, operationID).
		Scan(&sequence, &ledgerID, &stored.record, &recordDigest, &previousDigest, &chainDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return storedOperation{}, false, nil
	}
	if err != nil || len(recordDigest) != sha256.Size || len(previousDigest) != sha256.Size || len(chainDigest) != sha256.Size {
		return storedOperation{}, false, audit.ErrUnavailable
	}
	var rd, pd, cd [sha256.Size]byte
	copy(rd[:], recordDigest)
	copy(pd[:], previousDigest)
	copy(cd[:], chainDigest)
	receipt, err := audit.NewReceipt(ledgerID, sequence, operationID, rd, pd, cd)
	if err != nil {
		return storedOperation{}, false, audit.ErrUnavailable
	}
	stored.receipt = receipt
	return stored, true, nil
}

func verifyHead(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, ledgerID string, sequence uint64, head []byte) error {
	if sequence == 0 {
		genesis, err := audit.GenesisDigest(ledgerID)
		if err != nil || !bytes.Equal(head, genesis[:]) {
			return audit.ErrUnavailable
		}
		return nil
	}
	var storedSequence uint64
	var storedHead []byte
	if err := query.QueryRowContext(ctx, "SELECT sequence, chain_digest FROM audit_entries ORDER BY sequence DESC LIMIT 1").Scan(&storedSequence, &storedHead); err != nil || storedSequence != sequence || !bytes.Equal(storedHead, head) {
		return audit.ErrUnavailable
	}
	return nil
}

type immediateTx struct {
	conn *sql.Conn
	done bool
}

func beginImmediate(ctx context.Context, db *sql.DB) (*immediateTx, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &immediateTx{conn: conn}, nil
}

func (tx *immediateTx) commit(ctx context.Context) error {
	if tx.done {
		return audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, "COMMIT"); err != nil {
		_ = tx.conn.Close()
		tx.done = true
		return err
	}
	tx.done = true
	return tx.conn.Close()
}

func (tx *immediateTx) rollback() {
	if tx == nil || tx.done {
		return
	}
	_, _ = tx.conn.ExecContext(context.Background(), "ROLLBACK")
	tx.done = true
	_ = tx.conn.Close()
}
