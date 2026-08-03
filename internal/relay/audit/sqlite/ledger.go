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

const schemaVersion = 1

type Ledger struct{ db *sql.DB }

func Open(path string) (*Ledger, error) {
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
	if err := ledger.Verify(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
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

	if existing, found, err := lookupOperation(ctx, tx.conn, record.OperationID); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	} else if found {
		if !bytes.Equal(existing.record, canonical) {
			return audit.Receipt{}, audit.ErrConflict
		}
		return existing.receipt, nil
	}

	var ledgerID string
	var lastSequence uint64
	var previousBytes []byte
	if err := tx.conn.QueryRowContext(ctx, "SELECT ledger_id, last_sequence, chain_head FROM audit_metadata WHERE singleton = 1").Scan(&ledgerID, &lastSequence, &previousBytes); err != nil || len(previousBytes) != sha256.Size || lastSequence >= audit.MaxJSONSafeSequence {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	if err := verifyHead(ctx, tx.conn, ledgerID, lastSequence, previousBytes); err != nil {
		return audit.Receipt{}, err
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
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO audit_entries
		(sequence, operation_id, canonical_record, record_digest, previous_chain_digest, chain_digest, canonical_receipt)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sequence, record.OperationID, canonical, recordDigest[:], previous[:], chainDigest[:], canonicalReceipt); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	result, err := tx.conn.ExecContext(ctx, "UPDATE audit_metadata SET last_sequence = ?, chain_head = ? WHERE singleton = 1 AND last_sequence = ? AND chain_head = ?", sequence, chainDigest[:], lastSequence, previous[:])
	if err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	if err := tx.commit(ctx); err != nil {
		return audit.Receipt{}, audit.ErrUnavailable
	}
	return receipt, nil
}

func (l *Ledger) Verify(ctx context.Context) error {
	if l == nil || l.db == nil || ctx == nil {
		return audit.ErrUnavailable
	}
	var ledgerID string
	var lastSequence uint64
	var head []byte
	if err := l.db.QueryRowContext(ctx, "SELECT ledger_id, last_sequence, chain_head FROM audit_metadata WHERE singleton = 1").Scan(&ledgerID, &lastSequence, &head); err != nil || len(head) != sha256.Size {
		return audit.ErrUnavailable
	}
	genesis, err := audit.GenesisDigest(ledgerID)
	if err != nil {
		return audit.ErrUnavailable
	}
	previous := genesis
	rows, err := l.db.QueryContext(ctx, `SELECT sequence, operation_id, canonical_record, record_digest, previous_chain_digest, chain_digest, canonical_receipt FROM audit_entries ORDER BY sequence`)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer rows.Close()
	var count uint64
	for rows.Next() {
		count++
		var sequence uint64
		var operationID string
		var canonical, recordBytes, previousBytes, chainBytes, receiptBytes []byte
		if err := rows.Scan(&sequence, &operationID, &canonical, &recordBytes, &previousBytes, &chainBytes, &receiptBytes); err != nil || sequence != count || len(recordBytes) != sha256.Size || len(previousBytes) != sha256.Size || len(chainBytes) != sha256.Size {
			return audit.ErrUnavailable
		}
		if err := audit.ValidateCanonicalRecord(canonical); err != nil {
			return audit.ErrUnavailable
		}
		recordDigest := audit.RecordDigest(canonical)
		if !bytes.Equal(recordBytes, recordDigest[:]) || !bytes.Equal(previousBytes, previous[:]) {
			return audit.ErrUnavailable
		}
		chainDigest, err := audit.ChainDigest(sequence, previous, recordDigest)
		if err != nil || !bytes.Equal(chainBytes, chainDigest[:]) {
			return audit.ErrUnavailable
		}
		receipt, err := audit.NewReceipt(ledgerID, sequence, operationID, recordDigest, previous, chainDigest)
		if err != nil {
			return audit.ErrUnavailable
		}
		expectedReceipt, err := audit.CanonicalReceipt(receipt)
		if err != nil || !bytes.Equal(receiptBytes, expectedReceipt) {
			return audit.ErrUnavailable
		}
		previous = chainDigest
	}
	if rows.Err() != nil || count != lastSequence || !bytes.Equal(head, previous[:]) {
		return audit.ErrUnavailable
	}
	return nil
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
	if version == schemaVersion {
		return tx.commit(ctx)
	}
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
		if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
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
	if _, err := tx.conn.ExecContext(ctx, "INSERT INTO audit_metadata VALUES (1, 1, ?, 0, ?)", ledgerID.String(), genesis[:]); err != nil {
		return audit.ErrUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
		return audit.ErrUnavailable
	}
	return tx.commit(ctx)
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
