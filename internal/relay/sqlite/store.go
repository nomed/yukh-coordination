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

const schemaVersion = 5

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
	if version < 0 || version > schemaVersion {
		return fmt.Errorf("unsupported sqlite schema version %d", version)
	}
	if version == schemaVersion {
		return tx.commit(ctx)
	}

	if version == 1 {
		migrationStatements := []string{
			"ALTER TABLE accepted_records ADD COLUMN signing_key_id TEXT",
			"ALTER TABLE accepted_records ADD COLUMN signature_algorithm TEXT",
			"ALTER TABLE accepted_records ADD COLUMN signature BLOB CHECK (signature IS NULL OR length(signature) > 0)",
		}
		for _, statement := range migrationStatements {
			if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migrate sqlite relay signatures: %w", err)
			}
		}
		version = 2
	}
	if version == 2 {
		migrationStatements := []string{
			"ALTER TABLE transcripts ADD COLUMN canonical_metadata BLOB",
			"ALTER TABLE transcripts ADD COLUMN metadata_digest TEXT",
			"ALTER TABLE transcripts ADD COLUMN lifecycle TEXT",
		}
		for _, statement := range migrationStatements {
			if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migrate sqlite channel metadata: %w", err)
			}
		}
		version = 3
	}
	if version == 3 {
		if err := migrateLifecyclePreparation(ctx, tx.conn); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		if err := migrateLifecycleRemoval(ctx, tx.conn); err != nil {
			return err
		}
		if _, err := tx.conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
			return fmt.Errorf("set sqlite schema version: %w", err)
		}
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
			canonical_metadata BLOB NOT NULL,
			metadata_digest TEXT NOT NULL,
			lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active', 'redacted', 'deleted')),
			completeness TEXT NOT NULL CHECK (completeness IN ('complete', 'incomplete')),
			PRIMARY KEY (tenant_id, channel_id, transcript_epoch),
			FOREIGN KEY (tenant_id, channel_id)
				REFERENCES channel_identities (tenant_id, channel_id)
		) STRICT`,
		lifecyclePoliciesTable,
		transcriptPolicyBindingsTable,
		lifecycleOperationsTable,
		lifecycleActiveOperationIndex,
		lifecyclePayloadTombstonesTable,
		lifecycleIdentifierTombstonesTable,
		lifecycleReceiptTombstoneIndex,
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
			signing_key_id TEXT NOT NULL,
			signature_algorithm TEXT NOT NULL,
			unsigned_receipt_preimage BLOB NOT NULL,
			signature BLOB CHECK (signature IS NULL OR length(signature) > 0),
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

const lifecyclePoliciesTable = `CREATE TABLE lifecycle_policies (
	policy_digest TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	policy_epoch INTEGER NOT NULL CHECK (policy_epoch > 0),
	canonical_policy BLOB NOT NULL,
	active_retention_millis INTEGER NOT NULL CHECK (active_retention_millis > 0),
	export_mode TEXT NOT NULL CHECK (export_mode IN ('forbidden', 'permitted', 'required'))
) STRICT`

const transcriptPolicyBindingsTable = `CREATE TABLE transcript_policy_bindings (
	tenant_id TEXT NOT NULL,
	channel_id TEXT NOT NULL,
	transcript_epoch TEXT NOT NULL,
	policy_digest TEXT NOT NULL,
	policy_id TEXT NOT NULL,
	policy_epoch INTEGER NOT NULL CHECK (policy_epoch > 0),
	retention_deadline TEXT NOT NULL,
	PRIMARY KEY (tenant_id, channel_id, transcript_epoch),
	FOREIGN KEY (tenant_id, channel_id, transcript_epoch)
		REFERENCES transcripts (tenant_id, channel_id, transcript_epoch),
	FOREIGN KEY (policy_digest) REFERENCES lifecycle_policies (policy_digest)
) STRICT`

const lifecycleOperationsTable = `CREATE TABLE lifecycle_operations (
	operation_id TEXT PRIMARY KEY,
	intent_digest TEXT NOT NULL,
	canonical_intent BLOB NOT NULL,
	tenant_id TEXT NOT NULL,
	channel_id TEXT NOT NULL,
	transcript_epoch TEXT NOT NULL,
	policy_digest TEXT NOT NULL,
	requested_at TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN (
		'reserved', 'export_satisfied', 'marker_persisted', 'receipt_signed',
		'payload_removed', 'backups_pending', 'completed'
	)),
	export_manifest_digest TEXT,
	export_custody_receipt_digest TEXT,
	canonical_marker BLOB,
	canonical_receipt_preimage BLOB,
	receipt_signature BLOB CHECK (receipt_signature IS NULL OR length(receipt_signature) = 64),
	payload_removal_digest TEXT,
	FOREIGN KEY (tenant_id, channel_id, transcript_epoch)
		REFERENCES transcript_policy_bindings (tenant_id, channel_id, transcript_epoch)
) STRICT`

const lifecycleOperationsTableV4 = `CREATE TABLE lifecycle_operations (
	operation_id TEXT PRIMARY KEY,
	intent_digest TEXT NOT NULL,
	canonical_intent BLOB NOT NULL,
	tenant_id TEXT NOT NULL,
	channel_id TEXT NOT NULL,
	transcript_epoch TEXT NOT NULL,
	policy_digest TEXT NOT NULL,
	requested_at TEXT NOT NULL,
	state TEXT NOT NULL CHECK (state IN (
		'reserved', 'export_satisfied', 'marker_persisted', 'receipt_signed',
		'payload_removed', 'backups_pending', 'completed'
	)),
	export_manifest_digest TEXT,
	export_custody_receipt_digest TEXT,
	canonical_marker BLOB,
	canonical_receipt_preimage BLOB,
	FOREIGN KEY (tenant_id, channel_id, transcript_epoch)
		REFERENCES transcript_policy_bindings (tenant_id, channel_id, transcript_epoch)
) STRICT`

const lifecycleActiveOperationIndex = `CREATE UNIQUE INDEX lifecycle_one_active_operation
	ON lifecycle_operations (tenant_id, channel_id, transcript_epoch)
	WHERE state != 'completed'`

const lifecyclePayloadTombstonesTable = `CREATE TABLE lifecycle_payload_tombstones (
	operation_id TEXT NOT NULL,
	tenant_id TEXT NOT NULL,
	channel_id TEXT NOT NULL,
	transcript_epoch TEXT NOT NULL,
	server_sequence INTEGER NOT NULL CHECK (server_sequence > 0),
	event_id_digest TEXT NOT NULL,
	event_digest TEXT NOT NULL,
	receipt_id_digest TEXT NOT NULL,
	PRIMARY KEY (operation_id, server_sequence),
	FOREIGN KEY (operation_id) REFERENCES lifecycle_operations (operation_id)
) STRICT`

const lifecycleIdentifierTombstonesTable = `CREATE TABLE lifecycle_identifier_tombstones (
	tenant_id TEXT NOT NULL,
	channel_id TEXT NOT NULL,
	identifier_kind TEXT NOT NULL CHECK (identifier_kind IN ('event', 'receipt')),
	identifier_digest TEXT NOT NULL,
	operation_id TEXT NOT NULL,
	PRIMARY KEY (tenant_id, channel_id, identifier_kind, identifier_digest),
	FOREIGN KEY (operation_id) REFERENCES lifecycle_operations (operation_id)
) STRICT`

const lifecycleReceiptTombstoneIndex = `CREATE UNIQUE INDEX lifecycle_receipt_identifier_nonreuse
	ON lifecycle_identifier_tombstones (identifier_digest)
	WHERE identifier_kind = 'receipt'`

func migrateLifecyclePreparation(ctx context.Context, conn *sql.Conn) error {
	statements := []string{
		"ALTER TABLE transcripts ADD COLUMN completeness TEXT NOT NULL DEFAULT 'complete' CHECK (completeness IN ('complete', 'incomplete'))",
		lifecyclePoliciesTable,
		transcriptPolicyBindingsTable,
		lifecycleOperationsTableV4,
		lifecycleActiveOperationIndex,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite lifecycle preparation: %w", err)
		}
	}
	return nil
}

func migrateLifecycleRemoval(ctx context.Context, conn *sql.Conn) error {
	statements := []string{
		"ALTER TABLE lifecycle_operations ADD COLUMN receipt_signature BLOB CHECK (receipt_signature IS NULL OR length(receipt_signature) = 64)",
		"ALTER TABLE lifecycle_operations ADD COLUMN payload_removal_digest TEXT",
		lifecyclePayloadTombstonesTable,
		lifecycleIdentifierTombstonesTable,
		lifecycleReceiptTombstoneIndex,
	}
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite lifecycle removal: %w", err)
		}
	}
	return nil
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

	result, err := tx.conn.ExecContext(ctx,
		`INSERT INTO transcripts (tenant_id, channel_id, transcript_epoch, canonical_metadata, metadata_digest, lifecycle, completeness)
		 VALUES (?, ?, ?, ?, ?, ?, 'complete') ON CONFLICT DO NOTHING`,
		channel.Key.TenantID, channel.Key.ChannelID, channel.Key.TranscriptEpoch,
		channel.CanonicalMetadata, channel.MetadataDigest, channel.Lifecycle,
	)
	if err != nil {
		return fmt.Errorf("insert sqlite transcript: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read sqlite transcript insert result: %w", err)
	}
	if rows == 0 {
		existing, err := lookupChannel(ctx, tx.conn, channel.Key)
		if err != nil {
			return err
		}
		if !relay.SameChannel(existing, channel) {
			return relay.ErrChannelConflict
		}
	}
	return tx.commit(ctx)
}

func (s *Store) LookupChannel(ctx context.Context, key relay.ChannelKey) (relay.Channel, error) {
	if err := ctx.Err(); err != nil {
		return relay.Channel{}, err
	}
	if key.TenantID == "" || key.ChannelID == "" || key.TranscriptEpoch == "" {
		return relay.Channel{}, relay.ErrInvalidArgument
	}
	return lookupChannel(ctx, s.db, key)
}

func lookupChannel(ctx context.Context, query queryRower, key relay.ChannelKey) (relay.Channel, error) {
	channel := relay.Channel{Key: key}
	err := query.QueryRowContext(ctx,
		`SELECT identities.uri, transcripts.canonical_metadata, transcripts.metadata_digest, transcripts.lifecycle
		 FROM transcripts
		 JOIN channel_identities AS identities USING (tenant_id, channel_id)
		 WHERE transcripts.tenant_id = ? AND transcripts.channel_id = ? AND transcripts.transcript_epoch = ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch,
	).Scan(&channel.URI, &channel.CanonicalMetadata, &channel.MetadataDigest, &channel.Lifecycle)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.Channel{}, relay.ErrChannelNotFound
	}
	if err != nil {
		return relay.Channel{}, fmt.Errorf("look up sqlite channel metadata: %w", err)
	}
	if err := relay.ValidateChannel(channel); err != nil {
		return relay.Channel{}, fmt.Errorf("%w: incomplete channel metadata", relay.ErrChannelNotFound)
	}
	return relay.CloneChannel(channel), nil
}

func (s *Store) Append(ctx context.Context, intent relay.AppendIntent, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	return s.AppendChecked(ctx, intent, func(relay.AdmissionView) error { return nil }, prepare)
}

func (s *Store) AppendChecked(ctx context.Context, intent relay.AppendIntent, admit relay.Admit, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return relay.AppendResult{}, err
	}
	if err := relay.ValidateCheckedAppend(intent, admit, prepare); err != nil {
		return relay.AppendResult{}, err
	}

	tx, err := beginImmediate(ctx, s.db)
	if err != nil {
		return relay.AppendResult{}, err
	}
	defer tx.rollback()

	var sequence uint64
	var transcriptLifecycle string
	if err := tx.conn.QueryRowContext(ctx,
		`SELECT next_sequence, lifecycle FROM transcripts
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		intent.Channel.TenantID, intent.Channel.ChannelID, intent.Channel.TranscriptEpoch,
	).Scan(&sequence, &transcriptLifecycle); errors.Is(err, sql.ErrNoRows) {
		return relay.AppendResult{}, relay.ErrChannelNotFound
	} else if err != nil {
		return relay.AppendResult{}, fmt.Errorf("read sqlite transcript sequence: %w", err)
	}
	if transcriptLifecycle != "active" {
		return relay.AppendResult{}, relay.ErrTransitionConflict
	}
	var reusedEvent int
	if err := tx.conn.QueryRowContext(ctx, `SELECT 1 FROM lifecycle_identifier_tombstones
		WHERE tenant_id = ? AND channel_id = ? AND identifier_kind = 'event' AND identifier_digest = ?`,
		intent.Channel.TenantID, intent.Channel.ChannelID, identifierDigest("event", intent.EventID)).Scan(&reusedEvent); err == nil {
		return relay.AppendResult{}, relay.ErrEventIDCollision
	} else if !errors.Is(err, sql.ErrNoRows) {
		return relay.AppendResult{}, fmt.Errorf("check sqlite event tombstone: %w", err)
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
	if err := admit(sqliteAdmissionView{ctx: ctx, query: tx.conn, key: intent.Channel}); err != nil {
		return relay.AppendResult{}, err
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
	var reusedReceipt int
	if err := tx.conn.QueryRowContext(ctx, `SELECT 1 FROM lifecycle_identifier_tombstones
		WHERE identifier_kind = 'receipt' AND identifier_digest = ?`,
		identifierDigest("receipt", record.ReceiptID)).Scan(&reusedReceipt); err == nil {
		return relay.AppendResult{}, relay.ErrTransitionConflict
	} else if !errors.Is(err, sql.ErrNoRows) {
		return relay.AppendResult{}, fmt.Errorf("check sqlite receipt tombstone: %w", err)
	}

	if _, err := tx.conn.ExecContext(ctx,
		`INSERT INTO accepted_records (
			tenant_id, channel_id, transcript_epoch, server_sequence, event_id,
			canonical_event, event_digest, authenticated_binding,
			authorization_binding, receipt_id, signing_key_id,
			signature_algorithm, unsigned_receipt_preimage
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Channel.TenantID, record.Channel.ChannelID, record.Channel.TranscriptEpoch,
		record.Sequence, record.EventID, record.CanonicalEvent, record.EventDigest,
		record.AuthenticatedBinding, record.AuthorizationBinding, record.ReceiptID,
		record.SigningKeyID, record.SignatureAlgorithm,
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

type sqliteAdmissionView struct {
	ctx   context.Context
	query queryRower
	key   relay.ChannelKey
}

func (v sqliteAdmissionView) Lookup(eventID string) (relay.AcceptedRecord, error) {
	record, found, err := findRecord(v.ctx, v.query, v.key.TenantID, v.key.ChannelID, eventID)
	if err != nil {
		return relay.AcceptedRecord{}, err
	}
	if !found || record.Channel != v.key {
		return relay.AcceptedRecord{}, relay.ErrEventNotFound
	}
	return record, nil
}

func (v sqliteAdmissionView) Read(after uint64, limit int) ([]relay.AcceptedRecord, error) {
	if limit < 1 || limit > 1000 || after > math.MaxInt64 {
		return nil, relay.ErrInvalidArgument
	}
	rows, err := v.query.(interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	}).QueryContext(v.ctx, `SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		event_digest, authenticated_binding, authorization_binding, receipt_id,
		signing_key_id, signature_algorithm, unsigned_receipt_preimage, signature
		FROM accepted_records WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?
		AND server_sequence > ? ORDER BY server_sequence LIMIT ?`,
		v.key.TenantID, v.key.ChannelID, v.key.TranscriptEpoch, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]relay.AcceptedRecord, 0)
	for rows.Next() {
		record := relay.AcceptedRecord{Channel: relay.ChannelKey{TenantID: v.key.TenantID, ChannelID: v.key.ChannelID}}
		if err := rows.Scan(&record.Channel.TranscriptEpoch, &record.Sequence, &record.EventID, &record.CanonicalEvent, &record.EventDigest, &record.AuthenticatedBinding, &record.AuthorizationBinding, &record.ReceiptID, &record.SigningKeyID, &record.SignatureAlgorithm, &record.UnsignedReceiptPreimage, &record.Signature); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Store) Lookup(ctx context.Context, key relay.ChannelKey, eventID string) (relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return relay.AcceptedRecord{}, err
	}
	if key.TenantID == "" || key.ChannelID == "" || key.TranscriptEpoch == "" || eventID == "" {
		return relay.AcceptedRecord{}, relay.ErrInvalidArgument
	}
	var exists int
	if err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM transcripts
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch,
	).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return relay.AcceptedRecord{}, relay.ErrChannelNotFound
	} else if err != nil {
		return relay.AcceptedRecord{}, fmt.Errorf("look up sqlite transcript: %w", err)
	}
	record, found, err := findRecord(ctx, s.db, key.TenantID, key.ChannelID, eventID)
	if err != nil {
		return relay.AcceptedRecord{}, err
	}
	if !found {
		return relay.AcceptedRecord{}, relay.ErrEventNotFound
	}
	return record, nil
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

	var transcriptLifecycle string
	if err := s.db.QueryRowContext(ctx,
		`SELECT lifecycle FROM transcripts
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch,
	).Scan(&transcriptLifecycle); errors.Is(err, sql.ErrNoRows) {
		return nil, relay.ErrChannelNotFound
	} else if err != nil {
		return nil, fmt.Errorf("look up sqlite transcript: %w", err)
	}
	if transcriptLifecycle == "deleted" {
		return []relay.AcceptedRecord{}, nil
	}
	cutoff := int64(math.MaxInt64)
	if transcriptLifecycle == "redacted" {
		var firstRemoved sql.NullInt64
		err := s.db.QueryRowContext(ctx, `SELECT MIN(server_sequence) FROM lifecycle_payload_tombstones
			WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
			key.TenantID, key.ChannelID, key.TranscriptEpoch).Scan(&firstRemoved)
		if err != nil {
			return nil, fmt.Errorf("read sqlite redaction boundary: %w", err)
		}
		if !firstRemoved.Valid {
			return []relay.AcceptedRecord{}, nil
		}
		cutoff = firstRemoved.Int64
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		        event_digest, authenticated_binding, authorization_binding,
		        receipt_id, signing_key_id, signature_algorithm,
		        unsigned_receipt_preimage, signature
		 FROM accepted_records
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?
		   AND server_sequence > ?
		   AND server_sequence < ?
		 ORDER BY server_sequence
		 LIMIT ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch, after, cutoff, limit,
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
			&record.AuthorizationBinding, &record.ReceiptID, &record.SigningKeyID,
			&record.SignatureAlgorithm, &record.UnsignedReceiptPreimage,
			&record.Signature,
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

func (s *Store) AttachSignature(ctx context.Context, attachment relay.SignatureAttachment) (relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return relay.AcceptedRecord{}, err
	}
	if err := relay.ValidateSignatureAttachment(attachment); err != nil {
		return relay.AcceptedRecord{}, err
	}

	tx, err := beginImmediate(ctx, s.db)
	if err != nil {
		return relay.AcceptedRecord{}, err
	}
	defer tx.rollback()

	record, found, err := findReceipt(ctx, tx.conn, attachment.Channel, attachment.ReceiptID)
	if err != nil {
		return relay.AcceptedRecord{}, err
	}
	if !found {
		return relay.AcceptedRecord{}, relay.ErrReceiptNotFound
	}
	if !bytes.Equal(record.UnsignedReceiptPreimage, attachment.UnsignedReceiptPreimage) {
		return relay.AcceptedRecord{}, relay.ErrSignatureCollision
	}
	if len(record.Signature) > 0 {
		if !bytes.Equal(record.Signature, attachment.Signature) {
			return relay.AcceptedRecord{}, relay.ErrSignatureCollision
		}
		if err := tx.commit(ctx); err != nil {
			return relay.AcceptedRecord{}, err
		}
		return record, nil
	}

	result, err := tx.conn.ExecContext(ctx,
		`UPDATE accepted_records SET signature = ?
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?
		   AND receipt_id = ? AND signature IS NULL`,
		attachment.Signature, attachment.Channel.TenantID, attachment.Channel.ChannelID,
		attachment.Channel.TranscriptEpoch, attachment.ReceiptID,
	)
	if err != nil {
		return relay.AcceptedRecord{}, fmt.Errorf("attach sqlite receipt signature: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return relay.AcceptedRecord{}, fmt.Errorf("read sqlite signature update result: %w", err)
	}
	if rows != 1 {
		return relay.AcceptedRecord{}, fmt.Errorf("attach sqlite receipt signature: expected one row, got %d", rows)
	}
	if err := tx.commit(ctx); err != nil {
		return relay.AcceptedRecord{}, err
	}
	record.Signature = bytes.Clone(attachment.Signature)
	return record, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func findRecord(ctx context.Context, query queryRower, tenantID, channelID, eventID string) (relay.AcceptedRecord, bool, error) {
	record := relay.AcceptedRecord{Channel: relay.ChannelKey{TenantID: tenantID, ChannelID: channelID}}
	err := query.QueryRowContext(ctx,
		`SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		        event_digest, authenticated_binding, authorization_binding,
		        receipt_id, signing_key_id, signature_algorithm,
		        unsigned_receipt_preimage, signature
		 FROM accepted_records
		 WHERE tenant_id = ? AND channel_id = ? AND event_id = ?`,
		tenantID, channelID, eventID,
	).Scan(
		&record.Channel.TranscriptEpoch, &record.Sequence, &record.EventID,
		&record.CanonicalEvent, &record.EventDigest, &record.AuthenticatedBinding,
		&record.AuthorizationBinding, &record.ReceiptID, &record.SigningKeyID,
		&record.SignatureAlgorithm, &record.UnsignedReceiptPreimage,
		&record.Signature,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.AcceptedRecord{}, false, nil
	}
	if err != nil {
		return relay.AcceptedRecord{}, false, fmt.Errorf("look up sqlite event id: %w", err)
	}
	return record, true, nil
}

func findReceipt(ctx context.Context, conn *sql.Conn, key relay.ChannelKey, receiptID string) (relay.AcceptedRecord, bool, error) {
	record := relay.AcceptedRecord{Channel: relay.ChannelKey{TenantID: key.TenantID, ChannelID: key.ChannelID}}
	err := conn.QueryRowContext(ctx,
		`SELECT transcript_epoch, server_sequence, event_id, canonical_event,
		        event_digest, authenticated_binding, authorization_binding,
		        receipt_id, signing_key_id, signature_algorithm,
		        unsigned_receipt_preimage, signature
		 FROM accepted_records
		 WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND receipt_id = ?`,
		key.TenantID, key.ChannelID, key.TranscriptEpoch, receiptID,
	).Scan(
		&record.Channel.TranscriptEpoch, &record.Sequence, &record.EventID,
		&record.CanonicalEvent, &record.EventDigest, &record.AuthenticatedBinding,
		&record.AuthorizationBinding, &record.ReceiptID, &record.SigningKeyID,
		&record.SignatureAlgorithm, &record.UnsignedReceiptPreimage,
		&record.Signature,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return relay.AcceptedRecord{}, false, nil
	}
	if err != nil {
		return relay.AcceptedRecord{}, false, fmt.Errorf("look up sqlite receipt: %w", err)
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
