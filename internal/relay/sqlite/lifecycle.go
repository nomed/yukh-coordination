package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

const maxSQLiteRetentionMillis = uint64(math.MaxInt64 / int64(time.Millisecond))

// LifecyclePreparation is the non-destructive SQLite lifecycle capability.
// It shares the relay database transaction domain but is never returned as the
// ordinary relay.Store interface.
type LifecyclePreparation struct {
	store     *Store
	validator *protocol.Validator
	policies  map[string]lifecycle.Policy
}

var _ lifecycle.TranscriptLifecyclePreparationStore = (*LifecyclePreparation)(nil)

// NewLifecyclePreparation binds the exact retention policies already verified
// by the offline manifest provider. Signature verification is deliberately not
// duplicated in this storage adapter.
func NewLifecyclePreparation(store *Store, policies []lifecycle.Policy) (*LifecyclePreparation, error) {
	if store == nil || store.db == nil || len(policies) == 0 {
		return nil, lifecycle.ErrInvalidContract
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		return nil, lifecycle.ErrUnavailable
	}
	closed := make(map[string]lifecycle.Policy, len(policies))
	for _, policy := range policies {
		if lifecycle.ValidatePolicy(policy) != nil || policy.ActiveRetentionMillis > maxSQLiteRetentionMillis {
			return nil, lifecycle.ErrInvalidContract
		}
		if existing, found := closed[policy.PolicyDigest]; found && existing != policy {
			return nil, lifecycle.ErrConflict
		}
		closed[policy.PolicyDigest] = policy
	}
	return &LifecyclePreparation{store: store, validator: validator, policies: closed}, nil
}

func (s *LifecyclePreparation) Reserve(ctx context.Context, intent lifecycle.Intent) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	canonicalIntent, intentDigest, err := lifecycle.CanonicalIntent(intent)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()

	if existing, found, loadErr := loadLifecycleOperation(ctx, tx.conn, intent.OperationID); loadErr != nil {
		return lifecycle.Operation{}, loadErr
	} else if found {
		if existing.operation.IntentDigest != intentDigest || !bytes.Equal(existing.canonicalIntent, canonicalIntent) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(existing.operation), nil
	}

	policy, found := s.policies[intent.PolicyDigest]
	if !found || policy.PolicyID != intent.PolicyID || policy.PolicyEpoch != intent.PolicyEpoch || policy.ExportMode != intent.ExportMode {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	epoch := strconv.FormatUint(intent.Transcript.TranscriptEpoch, 10)
	var canonicalMetadata []byte
	var currentLifecycle, completeness string
	var nextSequence uint64
	queryErr := tx.conn.QueryRowContext(ctx, `SELECT canonical_metadata, lifecycle, completeness, next_sequence
		FROM transcripts WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch,
	).Scan(&canonicalMetadata, &currentLifecycle, &completeness, &nextSequence)
	if errors.Is(queryErr, sql.ErrNoRows) {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	if queryErr != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	metadata, metadataErr := s.validator.ValidateChannelMetadata(canonicalMetadata)
	if metadataErr != nil || metadata.TenantID != intent.Transcript.TenantID || metadata.ChannelID != intent.Transcript.ChannelID ||
		metadata.RetentionPolicyDigest != policy.PolicyDigest || metadata.RetentionEpoch != policy.PolicyEpoch ||
		currentLifecycle != string(lifecycle.Active) || completeness != "complete" || nextSequence <= 1 {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if err := validateLifecycleHighWater(ctx, tx.conn, intent, epoch, nextSequence-1); err != nil {
		return lifecycle.Operation{}, err
	}
	canonicalPolicy, err := lifecycle.CanonicalPolicy(policy)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	createdAt, err := time.Parse("2006-01-02T15:04:05.000Z", metadata.CreatedAt)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	retentionDeadline := createdAt.Add(time.Duration(policy.ActiveRetentionMillis) * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", retentionDeadline); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	if err := persistLifecyclePolicy(ctx, tx.conn, policy, canonicalPolicy); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := persistTranscriptPolicyBinding(ctx, tx.conn, intent, epoch, retentionDeadline); err != nil {
		return lifecycle.Operation{}, err
	}
	state := lifecycle.Reserved
	if policy.ExportMode != lifecycle.ExportRequired {
		state = lifecycle.ExportSatisfied
	}
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO lifecycle_operations (
		operation_id, intent_digest, canonical_intent, tenant_id, channel_id,
		transcript_epoch, policy_digest, requested_at, state
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, intent.OperationID, intentDigest,
		canonicalIntent, intent.Transcript.TenantID, intent.Transcript.ChannelID,
		epoch, intent.PolicyDigest, intent.RequestedAt, string(state)); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	return lifecycle.CloneOperation(lifecycle.Operation{Intent: intent, IntentDigest: intentDigest, State: state}), nil
}

func (s *LifecyclePreparation) BindExport(ctx context.Context, evidence lifecycle.ExportEvidence) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := lifecycle.ValidateExportEvidence(evidence); err != nil {
		return lifecycle.Operation{}, err
	}
	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, evidence.OperationID)
	if err != nil || !found {
		if err != nil {
			return lifecycle.Operation{}, err
		}
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	if stored.operation.IntentDigest != evidence.IntentDigest || stored.operation.Intent.ExportMode != lifecycle.ExportRequired {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if stored.exportManifestDigest != "" || stored.exportCustodyReceiptDigest != "" {
		if stored.exportManifestDigest != evidence.ManifestDigest || stored.exportCustodyReceiptDigest != evidence.CustodyReceiptDigest {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	if stored.operation.State != lifecycle.Reserved {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations
		SET export_manifest_digest = ?, export_custody_receipt_digest = ?, state = 'export_satisfied'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'reserved'`, evidence.ManifestDigest,
		evidence.CustodyReceiptDigest, evidence.OperationID, evidence.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.ExportSatisfied
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecyclePreparation) PersistMarker(ctx context.Context, persistence lifecycle.MarkerPersistence) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := lifecycle.ValidateMarkerPersistence(persistence); err != nil {
		return lifecycle.Operation{}, err
	}
	var marker lifecycle.Marker
	var preimage lifecycle.ReceiptPreimage
	if json.Unmarshal(persistence.CanonicalMarker, &marker) != nil || json.Unmarshal(persistence.CanonicalPreimage, &preimage) != nil {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, persistence.OperationID)
	if err != nil || !found {
		if err != nil {
			return lifecycle.Operation{}, err
		}
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	if stored.operation.IntentDigest != persistence.IntentDigest || !markerMatchesIntent(marker, stored.operation.Intent) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if stored.operation.State == lifecycle.MarkerPersisted {
		if !bytes.Equal(stored.operation.Marker, persistence.CanonicalMarker) || !bytes.Equal(stored.operation.Receipt, persistence.CanonicalPreimage) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	if stored.operation.State != lifecycle.ExportSatisfied {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	epoch := strconv.FormatUint(marker.Transcript.TranscriptEpoch, 10)
	result, err := tx.conn.ExecContext(ctx, `UPDATE transcripts
		SET lifecycle = ?, completeness = 'incomplete'
		WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND lifecycle = ?`,
		string(marker.ResultingLifecycle), marker.Transcript.TenantID, marker.Transcript.ChannelID,
		epoch, string(marker.PreviousLifecycle))
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	result, err = tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations
		SET canonical_marker = ?, canonical_receipt_preimage = ?, state = 'marker_persisted'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'export_satisfied'`,
		persistence.CanonicalMarker, persistence.CanonicalPreimage,
		persistence.OperationID, persistence.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.MarkerPersisted
	stored.operation.Marker = bytes.Clone(persistence.CanonicalMarker)
	stored.operation.Receipt = bytes.Clone(persistence.CanonicalPreimage)
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecyclePreparation) Inspect(ctx context.Context, operationID string) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	if lifecycle.ValidateOperationReference(lifecycle.OperationReference{OperationID: operationID, IntentDigest: "sha-256:" + string(bytes.Repeat([]byte{'0'}, 64))}) != nil {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	stored, found, err := loadLifecycleOperation(ctx, s.store.db, operationID)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	if !found {
		return lifecycle.Operation{}, lifecycle.ErrInvalidContract
	}
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecyclePreparation) InspectDue(ctx context.Context, query lifecycle.DueQuery) ([]lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := lifecycle.ValidateDueQuery(query); err != nil {
		return nil, err
	}
	rows, err := s.store.db.QueryContext(ctx, `SELECT operation_id FROM lifecycle_operations
		WHERE requested_at <= ? AND operation_id > ? AND state IN ('reserved', 'export_satisfied', 'marker_persisted')
		ORDER BY operation_id LIMIT ?`, query.WallTime, query.AfterOperationID, query.Limit)
	if err != nil {
		return nil, lifecycle.ErrUnavailable
	}
	defer rows.Close()
	ids := make([]string, 0, query.Limit)
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, lifecycle.ErrUnavailable
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil {
		return nil, lifecycle.ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, lifecycle.ErrUnavailable
	}
	operations := make([]lifecycle.Operation, 0, len(ids))
	for _, id := range ids {
		operation, err := s.Inspect(ctx, id)
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

type lifecycleOperationRow struct {
	operation                  lifecycle.Operation
	canonicalIntent            []byte
	exportManifestDigest       string
	exportCustodyReceiptDigest string
}

func loadLifecycleOperation(ctx context.Context, query queryRower, operationID string) (lifecycleOperationRow, bool, error) {
	var row lifecycleOperationRow
	var state string
	var exportManifestDigest, exportCustodyReceiptDigest sql.NullString
	err := query.QueryRowContext(ctx, `SELECT intent_digest, canonical_intent, state,
		export_manifest_digest, export_custody_receipt_digest, canonical_marker,
		canonical_receipt_preimage FROM lifecycle_operations WHERE operation_id = ?`, operationID).Scan(
		&row.operation.IntentDigest, &row.canonicalIntent, &state,
		&exportManifestDigest, &exportCustodyReceiptDigest,
		&row.operation.Marker, &row.operation.Receipt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return lifecycleOperationRow{}, false, nil
	}
	if err != nil {
		return lifecycleOperationRow{}, false, lifecycle.ErrUnavailable
	}
	row.exportManifestDigest = exportManifestDigest.String
	row.exportCustodyReceiptDigest = exportCustodyReceiptDigest.String
	if lifecycle.ValidateCanonical(row.canonicalIntent) != nil || json.Unmarshal(row.canonicalIntent, &row.operation.Intent) != nil {
		return lifecycleOperationRow{}, false, lifecycle.ErrUnavailable
	}
	_, digest, err := lifecycle.CanonicalIntent(row.operation.Intent)
	if err != nil || digest != row.operation.IntentDigest {
		return lifecycleOperationRow{}, false, lifecycle.ErrUnavailable
	}
	row.operation.State = lifecycle.SagaState(state)
	if !validStoredPreparation(row) {
		return lifecycleOperationRow{}, false, lifecycle.ErrUnavailable
	}
	return row, true, nil
}

func validStoredPreparation(row lifecycleOperationRow) bool {
	operation := row.operation
	exportBound := row.exportManifestDigest != "" && row.exportCustodyReceiptDigest != ""
	exportEmpty := row.exportManifestDigest == "" && row.exportCustodyReceiptDigest == ""
	validExport := exportEmpty
	if operation.Intent.ExportMode == lifecycle.ExportRequired {
		validExport = exportBound && lifecycle.ValidateExportEvidence(lifecycle.ExportEvidence{
			OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest,
			ManifestDigest: row.exportManifestDigest, CustodyReceiptDigest: row.exportCustodyReceiptDigest,
		}) == nil
	}
	switch operation.State {
	case lifecycle.Reserved, lifecycle.ExportSatisfied:
		return len(operation.Marker) == 0 && len(operation.Receipt) == 0 &&
			(operation.State != lifecycle.Reserved || operation.Intent.ExportMode == lifecycle.ExportRequired && exportEmpty) &&
			(operation.State != lifecycle.ExportSatisfied || validExport)
	case lifecycle.MarkerPersisted:
		return validExport && lifecycle.ValidateMarkerPersistence(lifecycle.MarkerPersistence{
			OperationID: operation.Intent.OperationID, IntentDigest: operation.IntentDigest,
			CanonicalMarker: operation.Marker, CanonicalPreimage: operation.Receipt,
		}) == nil
	default:
		return false
	}
}

func persistLifecyclePolicy(ctx context.Context, conn *sql.Conn, policy lifecycle.Policy, canonical []byte) error {
	if _, err := conn.ExecContext(ctx, `INSERT INTO lifecycle_policies (
		policy_digest, policy_id, policy_epoch, canonical_policy,
		active_retention_millis, export_mode
	) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, policy.PolicyDigest,
		policy.PolicyID, policy.PolicyEpoch, canonical, policy.ActiveRetentionMillis,
		string(policy.ExportMode)); err != nil {
		return lifecycle.ErrUnavailable
	}
	var existingID, existingMode string
	var existingEpoch, existingRetention uint64
	var existingCanonical []byte
	if err := conn.QueryRowContext(ctx, `SELECT policy_id, policy_epoch, canonical_policy,
		active_retention_millis, export_mode FROM lifecycle_policies WHERE policy_digest = ?`,
		policy.PolicyDigest).Scan(&existingID, &existingEpoch, &existingCanonical,
		&existingRetention, &existingMode); err != nil {
		return lifecycle.ErrUnavailable
	}
	if existingID != policy.PolicyID || existingEpoch != policy.PolicyEpoch ||
		existingRetention != policy.ActiveRetentionMillis || existingMode != string(policy.ExportMode) ||
		!bytes.Equal(existingCanonical, canonical) {
		return lifecycle.ErrConflict
	}
	return nil
}

func persistTranscriptPolicyBinding(ctx context.Context, conn *sql.Conn, intent lifecycle.Intent, epoch, deadline string) error {
	if _, err := conn.ExecContext(ctx, `INSERT INTO transcript_policy_bindings (
		tenant_id, channel_id, transcript_epoch, policy_digest, policy_id,
		policy_epoch, retention_deadline
	) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, intent.Transcript.TenantID,
		intent.Transcript.ChannelID, epoch, intent.PolicyDigest, intent.PolicyID,
		intent.PolicyEpoch, deadline); err != nil {
		return lifecycle.ErrUnavailable
	}
	var digest, id, storedDeadline string
	var policyEpoch uint64
	if err := conn.QueryRowContext(ctx, `SELECT policy_digest, policy_id, policy_epoch,
		retention_deadline FROM transcript_policy_bindings
		WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ?`,
		intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch).Scan(
		&digest, &id, &policyEpoch, &storedDeadline); err != nil {
		return lifecycle.ErrUnavailable
	}
	if digest != intent.PolicyDigest || id != intent.PolicyID || policyEpoch != intent.PolicyEpoch || storedDeadline != deadline {
		return lifecycle.ErrConflict
	}
	return nil
}

func validateLifecycleHighWater(ctx context.Context, conn *sql.Conn, intent lifecycle.Intent, epoch string, highWater uint64) error {
	var receiptID string
	var signature []byte
	err := conn.QueryRowContext(ctx, `SELECT receipt_id, signature FROM accepted_records
		WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND server_sequence = ?`,
		intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch, highWater).Scan(&receiptID, &signature)
	if err != nil || len(signature) == 0 || receiptID != intent.HighWaterReceiptReference {
		return lifecycle.ErrConflict
	}
	for _, sequence := range intent.Target.Sequences {
		if sequence > highWater {
			return lifecycle.ErrConflict
		}
		var targetSignature []byte
		if err := conn.QueryRowContext(ctx, `SELECT signature FROM accepted_records
			WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND server_sequence = ?`,
			intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch, sequence).Scan(&targetSignature); err != nil || len(targetSignature) == 0 {
			return lifecycle.ErrConflict
		}
	}
	return nil
}

func markerMatchesIntent(marker lifecycle.Marker, intent lifecycle.Intent) bool {
	return marker.OperationID == intent.OperationID && marker.Transcript == intent.Transcript &&
		marker.PolicyDigest == intent.PolicyDigest && marker.HighWaterReceiptReference == intent.HighWaterReceiptReference &&
		marker.AuthorizingAuditReceipt == intent.AuthorizingAuditReceipt && marker.Target.Kind == intent.Target.Kind &&
		slices.Equal(marker.Target.Sequences, intent.Target.Sequences)
}

func exactlyOne(result sql.Result) error {
	if result == nil {
		return lifecycle.ErrUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return lifecycle.ErrUnavailable
	}
	return nil
}
