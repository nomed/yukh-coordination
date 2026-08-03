// Package sqlite implements the durable single-node relay store.
package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"

	"github.com/nomed/yukh-coordination/internal/relay"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type Store struct {
	db *sql.DB
}

var _ relay.Store = (*Store)(nil)

// Open opens or creates a relay database and applies the exact reference
// durability profile. One connection deliberately serializes writers; the DSN
// reapplies connection-local safety pragmas if that connection is replaced.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, relay.ErrInvalidArgument
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve sqlite relay path: %w", err)
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     absolutePath,
		RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=wal&_synchronous=full",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite relay store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.configure(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) configure(ctx context.Context) error {
	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("configure sqlite journal mode: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("configure sqlite journal mode: requested wal, got %q", journalMode)
	}
	pragmas := []string{
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, statement := range pragmas {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure sqlite relay store: %w", err)
		}
	}
	return nil
}

func (s *Store) migrate(ctx context.Context) error {
	tx, err := beginImmediate(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.rollback()

	var version int
	if err := tx.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read sqlite schema version: %w", err)
	}
	if version != 0 && version != schemaVersion {
		return fmt.Errorf("unsupported sqlite schema version %d", version)
	}
	if version == schemaVersion {
		return tx.commit(ctx)
	}

	statements := []string{
		`CREATE TABLE channel_identities (
			tenant_id TEXT NOT NULL,
			channel_id TEXT NOT NULL,
			uri TEXT NOT NULL,
			PRIMARY KEY (tenant_id, channel_id),
			UNIQUE (tenant_id, uri)
		) STRICT`,
		`CREATE TABLE transcripts (
			tenant_id TEXT NOT NULL,
			channel_id TEXT NOT NULL,
			transcript_epoch TEXT NOT NULL,
			next_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
			PRIMARY KEY (tenant_id, channel_id, transcript_epoch),
			FOREIGN KEY (tenant_id, channel_id)
				REFERENCES channel_identities (tenant_id, channel_id)
		) STRICT`,
		`CREATE TABLE accepted_records (
			tenant_id TEXT NOT NULL,
			channel_id TEXT NOT NULL,
			transcript_epoch TEXT NOT NULL,
			server_sequence INTEGER NOT NULL CHECK (server_sequence > 0),
			event_id TEXT NOT NULL,
			canonical_event BLOB NOT NULL,
			event_digest TEXT NOT NULL,
			authenticated_binding BLOB NOT NULL,
			authorization_binding BLOB NOT NULL,
			receipt_id TEXT NOT NULL,
			unsigned_receipt_preimage BLOB NOT NULL,
			PRIMARY KEY (tenant_id, channel_id, event_id),
			UNIQUE (receipt_id),
			UNIQUE (tenant_id, channel_id, transcript_epoch, server_sequence),
			FOREIGN KEY (tenant_id, channel_id, transcript_epoch)
				REFERENCES transcripts (tenant_id, channel_id, transcript_epoch)
		) STRICT`,
		fmt.Sprintf("PRAGMA user_version=%d", schemaVersion),
	}
	for _, statement := range statements {
		if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite relay store: %w", err)
		}
	}
	return tx.commit(ctx)
}

func (s *Store) CreateChannel(ctx context.Context, channel relay.Channel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := relay.ValidateChannel(channel); err != nil {
		return err
	}

	tx, err := beginImmediate(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.rollback()

	var existingURI string
	err = tx.conn.QueryRowContext(ctx,
		"SELECT uri FROM channel_identities WHERE tenant_id = ? AND channel_id = ?",
		channel.Key.TenantID, channel.Key.ChannelID,
	).Scan(&existingURI)
	switch {
	case err == nil && existingURI != channel.URI:
		return relay.ErrChannelConflict
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		var mappedChannel string
		uriErr := tx.conn.QueryRowContext(ctx,
			"SELECT channel_id FROM channel_identities WHERE tenant_id = ? AND uri = ?",
			channel.Key.TenantID, channel.URI,
		).Scan(&mappedChannel)
		if uriErr == nil {
			return relay.ErrChannelConflict
		}
		if !errors.Is(uriErr, sql.ErrNoRows) {
			return fmt.Errorf("look up sqlite channel URI: %w", uriErr)
		}
		if _, err := tx.conn.ExecContext(ctx,
			"INSERT INTO channel_identities (tenant_id, channel_id, uri) VALUES (?, ?, ?)",
			channel.Key.TenantID, channel.Key.ChannelID, channel.URI,
		); err != nil {
			return fmt.Errorf("insert sqlite channel identity: %w", err)
		}
	default:
		return fmt.Errorf("look up sqlite channel identity: %w", err)
	}

	if _, err := tx.conn.ExecContext(ctx,
		`INSERT INTO transcripts (tenant_id, channel_id, transcript_epoch)
		 VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
		channel.Key.TenantID, channel.Key.ChannelID, channel.Key.TranscriptEpoch,
	); err != nil {
		return fmt.Errorf("insert sqlite transcript: %w", err)
	}
	return tx.commit(ctx)
}

func (s *Store) Append(ctx context.Context, intent relay.AppendIntent, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return relay.AppendResult{}, err
	}
	if err := relay.ValidateAppendIntent(intent, prepare); err != nil {
		return relay.AppendResult{}, err
	}

	tx, err := beginImmediate(ctx, s.db)
	if err != nil {
		return relay.AppendResult{}, err
	}
	defer tx.rollback()

	var sequence uint64
	if err := tx.conn.QueryRowContext(ctx,
		`SELECT next_sequence FROM transcripts
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		intent.Channel.TenantID, intent.Channel.ChannelID, intent.Channel.TranscriptEpoch,
	).Scan(&sequence); errors.Is(err, sql.ErrNoRows) {
		return relay.AppendResult{}, relay.ErrChannelNotFound
	} else if err != nil {
		return relay.AppendResult{}, fmt.Errorf("read sqlite transcript sequence: %w", err)
	}

	existing, found, err := findRecord(ctx, tx.conn, intent.Channel.TenantID, intent.Channel.ChannelID, intent.EventID)
	if err != nil {
		return relay.AppendResult{}, err
	}
	if found {
		if existing.Channel != intent.Channel || !bytes.Equal(existing.CanonicalEvent, intent.CanonicalEvent) {
			return relay.AppendResult{}, relay.ErrEventIDCollision
		}
		if err := tx.commit(ctx); err != nil {
			return relay.AppendResult{}, err
		}
		return relay.AppendResult{Outcome: relay.AppendOutcomeDuplicate, Record: existing}, nil
	}

	digest := relay.EventDigest(intent.CanonicalEvent)
	record, err := prepare(sequence, digest)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("prepare accepted record: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return relay.AppendResult{}, err
	}
	if err := relay.ValidatePreparedRecord(intent, sequence, digest, record); err != nil {
		return relay.AppendResult{}, err
	}

	if _, err := tx.conn.ExecContext(ctx,
		`INSERT INTO accepted_records (
			tenant_id, channel_id, transcript_epoch, server_sequence, event_id,
			canonical_event, event_digest, authenticated_binding,
			authorization_binding, receipt_id, unsigned_receipt_preimage
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Channel.TenantID, record.Channel.ChannelID, record.Channel.TranscriptEpoch,
		record.Sequence, record.EventID, record.CanonicalEvent, record.EventDigest,
		record.AuthenticatedBinding, record.AuthorizationBinding, record.ReceiptID,
		record.UnsignedReceiptPreimage,
	); err != nil {
		return relay.AppendResult{}, fmt.Errorf("insert sqlite accepted record: %w", err)
	}
	result, err := tx.conn.ExecContext(ctx,
		`UPDATE transcripts SET next_sequence = next_sequence + 1
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND next_sequence = ?`,
		intent.Channel.TenantID, intent.Channel.ChannelID, intent.Channel.TranscriptEpoch, sequence,
	)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("advance sqlite transcript sequence: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("read sqlite sequence update result: %w", err)
	}
	if rows != 1 {
		return relay.AppendResult{}, fmt.Errorf("advance sqlite transcript sequence: expected one row, got %d", rows)
	}
	if err := tx.commit(ctx); err != nil {
		return relay.AppendResult{}, err
	}
	return relay.AppendResult{Outcome: relay.AppendOutcomeAppended, Record: relay.CloneRecord(record)}, nil
}

func (s *Store) Read(ctx context.Context, key relay.ChannelKey, after uint64, limit int) ([]relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if key.TenantID == "" || key.ChannelID == "" || key.TranscriptEpoch == "" || limit < 1 || limit > 1000 {
		return nil, relay.ErrInvalidArgument
	}
	if after > math.MaxInt64 {
		return []relay.AcceptedRecord{}, nil
	}

	var exists int
	if err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM transcripts
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch,
	).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return nil, relay.ErrChannelNotFound
	} else if err != nil {
		return nil, fmt.Errorf("look up sqlite transcript: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		        event_digest, authenticated_binding, authorization_binding,
		        receipt_id, unsigned_receipt_preimage
		 FROM accepted_records
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?
		   AND server_sequence > ?
		 ORDER BY server_sequence
		 LIMIT ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch, after, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("read sqlite accepted records: %w", err)
	}
	defer rows.Close()

	records := make([]relay.AcceptedRecord, 0)
	for rows.Next() {
		record := relay.AcceptedRecord{Channel: relay.ChannelKey{TenantID: key.TenantID, ChannelID: key.ChannelID}}
		if err := rows.Scan(
			&record.Channel.TranscriptEpoch, &record.Sequence, &record.EventID,
			&record.CanonicalEvent, &record.EventDigest, &record.AuthenticatedBinding,
			&record.AuthorizationBinding, &record.ReceiptID, &record.UnsignedReceiptPreimage,
		); err != nil {
			return nil, fmt.Errorf("scan sqlite accepted record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sqlite accepted records: %w", err)
	}
	return records, nil
}

func findRecord(ctx context.Context, conn *sql.Conn, tenantID, channelID, eventID string) (relay.AcceptedRecord, bool, error) {
	record := relay.AcceptedRecord{Channel: relay.ChannelKey{TenantID: tenantID, ChannelID: channelID}}
	err := conn.QueryRowContext(ctx,
		`SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		        event_digest, authenticated_binding, authorization_binding,
		        receipt_id, unsigned_receipt_preimage
		 FROM accepted_records
		 WHERE tenant_id = ? AND channel_id = ? AND event_id = ?`,
		tenantID, channelID, eventID,
	).Scan(
		&record.Channel.TranscriptEpoch, &record.Sequence, &record.EventID,
		&record.CanonicalEvent, &record.EventDigest, &record.AuthenticatedBinding,
		&record.AuthorizationBinding, &record.ReceiptID, &record.UnsignedReceiptPreimage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.AcceptedRecord{}, false, nil
	}
	if err != nil {
		return relay.AcceptedRecord{}, false, fmt.Errorf("look up sqlite event id: %w", err)
	}
	return record, true, nil
}

type immediateTx struct {
	conn *sql.Conn
	done bool
}

func beginImmediate(ctx context.Context, db *sql.DB) (*immediateTx, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire sqlite connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("begin sqlite transaction: %w", err)
	}
	return &immediateTx{conn: conn}, nil
}

func (tx *immediateTx) commit(ctx context.Context) error {
	if tx.done {
		return nil
	}
	if _, err := tx.conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("%w: %v", relay.ErrCommitIndeterminate, err)
	}
	tx.done = true
	_ = tx.conn.Close()
	return nil
}

func (tx *immediateTx) rollback() {
	if tx.done {
		return
	}
	_, _ = tx.conn.ExecContext(context.Background(), "ROLLBACK")
	tx.done = true
	_ = tx.conn.Close()
}
