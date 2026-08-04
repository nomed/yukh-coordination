package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	"github.com/nomed/yukh-coordination/internal/relay/lifecycle"
)

const (
	identifierDigestDomain = "yukh.lifecycle-identifier-tombstone.v0.1\x00"
	removalDigestDomain    = "yukh.lifecycle-payload-removal.v0.1\x00"
)

// LifecycleSignatureRemoval owns verified signature attachment and synthetic
// primary-store removal only. It has neither signing nor backup authority.
type LifecycleSignatureRemoval struct {
	store    *Store
	verifier lifecycle.ReceiptSignatureVerifier
}

var _ lifecycle.TranscriptLifecycleSignatureRemovalStore = (*LifecycleSignatureRemoval)(nil)

func NewLifecycleSignatureRemoval(store *Store, verifier lifecycle.ReceiptSignatureVerifier) (*LifecycleSignatureRemoval, error) {
	if store == nil || store.db == nil || nilInterface(verifier) {
		return nil, lifecycle.ErrInvalidContract
	}
	return &LifecycleSignatureRemoval{store: store, verifier: verifier}, nil
}

func (s *LifecycleSignatureRemoval) AttachSignature(ctx context.Context, attachment lifecycle.SignatureAttachment) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := lifecycle.ValidateSignatureAttachment(attachment); err != nil {
		return lifecycle.Operation{}, err
	}
	stored, found, err := loadLifecycleOperation(ctx, s.store.db, attachment.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if stored.operation.IntentDigest != attachment.IntentDigest || !bytes.Equal(stored.operation.Receipt, attachment.ReceiptPreimage) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if stored.operation.State == lifecycle.ReceiptSigned || stored.operation.State == lifecycle.PayloadRemoved {
		if !bytes.Equal(stored.operation.Signature, attachment.Signature) {
			return lifecycle.Operation{}, lifecycle.ErrConflict
		}
		if err := s.verifyStoredSignature(ctx, stored.operation); err != nil {
			return lifecycle.Operation{}, err
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	if stored.operation.State != lifecycle.MarkerPersisted {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	var receipt lifecycle.ReceiptPreimage
	if json.Unmarshal(stored.operation.Receipt, &receipt) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	_, signingBytes, err := lifecycle.CanonicalReceiptPreimage(receipt)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if err := s.verifier.VerifyLifecycleReceipt(ctx, receipt.SigningKeyID, receipt.SignatureAlgorithm, signingBytes, attachment.Signature); err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}

	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err = loadLifecycleOperation(ctx, tx.conn, attachment.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if stored.operation.IntentDigest != attachment.IntentDigest || !bytes.Equal(stored.operation.Receipt, attachment.ReceiptPreimage) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if stored.operation.State != lifecycle.MarkerPersisted {
		if (stored.operation.State == lifecycle.ReceiptSigned || stored.operation.State == lifecycle.PayloadRemoved) && bytes.Equal(stored.operation.Signature, attachment.Signature) {
			if tx.commit(ctx) != nil {
				return lifecycle.Operation{}, lifecycle.ErrUnavailable
			}
			return lifecycle.CloneOperation(stored.operation), nil
		}
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations
		SET receipt_signature = ?, state = 'receipt_signed'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'marker_persisted'`,
		attachment.Signature, attachment.OperationID, attachment.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.ReceiptSigned
	stored.operation.Signature = bytes.Clone(attachment.Signature)
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecycleSignatureRemoval) RemovePayload(ctx context.Context, reference lifecycle.OperationReference) (lifecycle.Operation, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, err
	}
	if err := lifecycle.ValidateOperationReference(reference); err != nil {
		return lifecycle.Operation{}, err
	}
	preflight, found, err := loadLifecycleOperation(ctx, s.store.db, reference.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if preflight.operation.IntentDigest != reference.IntentDigest {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if preflight.operation.State == lifecycle.ReceiptSigned || preflight.operation.State == lifecycle.PayloadRemoved {
		if err := s.verifyStoredSignature(ctx, preflight.operation); err != nil {
			return lifecycle.Operation{}, err
		}
	} else {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	tx, err := beginImmediate(ctx, s.store.db)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	defer tx.rollback()
	stored, found, err := loadLifecycleOperation(ctx, tx.conn, reference.OperationID)
	if err != nil || !found {
		return lifecycle.Operation{}, closedFound(err, found)
	}
	if stored.operation.IntentDigest != reference.IntentDigest {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if !bytes.Equal(stored.operation.Signature, preflight.operation.Signature) || !bytes.Equal(stored.operation.Receipt, preflight.operation.Receipt) {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	if stored.operation.State == lifecycle.PayloadRemoved {
		if !validateRemovalEvidence(ctx, tx.conn, stored) {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		if tx.commit(ctx) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
		return lifecycle.CloneOperation(stored.operation), nil
	}
	if stored.operation.State != lifecycle.ReceiptSigned {
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	removed, err := selectRemovalRecords(ctx, tx.conn, stored.operation.Intent)
	if err != nil || len(removed) == 0 {
		if err != nil {
			return lifecycle.Operation{}, err
		}
		return lifecycle.Operation{}, lifecycle.ErrConflict
	}
	for _, record := range removed {
		if err := insertRemovalEvidence(ctx, tx.conn, stored.operation.Intent.OperationID, stored.operation.Intent.Transcript, record); err != nil {
			return lifecycle.Operation{}, err
		}
		result, deleteErr := tx.conn.ExecContext(ctx, `DELETE FROM accepted_records
			WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND server_sequence = ?`,
			stored.operation.Intent.Transcript.TenantID, stored.operation.Intent.Transcript.ChannelID,
			strconv.FormatUint(stored.operation.Intent.Transcript.TranscriptEpoch, 10), record.sequence)
		if deleteErr != nil || exactlyOne(result) != nil {
			return lifecycle.Operation{}, lifecycle.ErrUnavailable
		}
	}
	evidenceRecords := make([]removalRecord, 0, len(removed))
	for _, record := range removed {
		record.eventID = identifierDigest("event", record.eventID)
		record.receiptID = identifierDigest("receipt", record.receiptID)
		evidenceRecords = append(evidenceRecords, record)
	}
	digest := removalDigest(evidenceRecords)
	result, err := tx.conn.ExecContext(ctx, `UPDATE lifecycle_operations
		SET payload_removal_digest = ?, state = 'payload_removed'
		WHERE operation_id = ? AND intent_digest = ? AND state = 'receipt_signed'`,
		digest, reference.OperationID, reference.IntentDigest)
	if err != nil || exactlyOne(result) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	if tx.commit(ctx) != nil {
		return lifecycle.Operation{}, lifecycle.ErrUnavailable
	}
	stored.operation.State = lifecycle.PayloadRemoved
	stored.payloadRemovalDigest = digest
	return lifecycle.CloneOperation(stored.operation), nil
}

func (s *LifecycleSignatureRemoval) verifyStoredSignature(ctx context.Context, operation lifecycle.Operation) error {
	var receipt lifecycle.ReceiptPreimage
	if json.Unmarshal(operation.Receipt, &receipt) != nil {
		return lifecycle.ErrUnavailable
	}
	_, signingBytes, err := lifecycle.CanonicalReceiptPreimage(receipt)
	if err != nil {
		return lifecycle.ErrUnavailable
	}
	if err := s.verifier.VerifyLifecycleReceipt(ctx, receipt.SigningKeyID, receipt.SignatureAlgorithm, signingBytes, operation.Signature); err != nil {
		return lifecycle.ErrUnavailable
	}
	return nil
}

type removalRecord struct {
	sequence    uint64
	eventID     string
	eventDigest string
	receiptID   string
}

func selectRemovalRecords(ctx context.Context, conn *sql.Conn, intent lifecycle.Intent) ([]removalRecord, error) {
	epoch := strconv.FormatUint(intent.Transcript.TranscriptEpoch, 10)
	if intent.Action == lifecycle.DeleteTranscript {
		rows, err := conn.QueryContext(ctx, `SELECT server_sequence, event_id, event_digest, receipt_id
			FROM accepted_records WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? ORDER BY server_sequence`,
			intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch)
		if err != nil {
			return nil, lifecycle.ErrUnavailable
		}
		defer rows.Close()
		var records []removalRecord
		for rows.Next() {
			var record removalRecord
			if rows.Scan(&record.sequence, &record.eventID, &record.eventDigest, &record.receiptID) != nil {
				return nil, lifecycle.ErrUnavailable
			}
			records = append(records, record)
		}
		if rows.Err() != nil {
			return nil, lifecycle.ErrUnavailable
		}
		return records, nil
	}
	records := make([]removalRecord, 0, len(intent.Target.Sequences))
	for _, sequence := range intent.Target.Sequences {
		var record removalRecord
		err := conn.QueryRowContext(ctx, `SELECT server_sequence, event_id, event_digest, receipt_id
			FROM accepted_records WHERE tenant_id = ? AND channel_id = ? AND transcript_epoch = ? AND server_sequence = ?`,
			intent.Transcript.TenantID, intent.Transcript.ChannelID, epoch, sequence).Scan(
			&record.sequence, &record.eventID, &record.eventDigest, &record.receiptID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, lifecycle.ErrConflict
		}
		if err != nil {
			return nil, lifecycle.ErrUnavailable
		}
		records = append(records, record)
	}
	return records, nil
}

func insertRemovalEvidence(ctx context.Context, conn *sql.Conn, operationID string, transcript lifecycle.TranscriptKey, record removalRecord) error {
	eventID := identifierDigest("event", record.eventID)
	receiptID := identifierDigest("receipt", record.receiptID)
	if _, err := conn.ExecContext(ctx, `INSERT INTO lifecycle_payload_tombstones
		(operation_id, tenant_id, channel_id, transcript_epoch, server_sequence, event_id_digest, event_digest, receipt_id_digest)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, operationID, transcript.TenantID, transcript.ChannelID,
		strconv.FormatUint(transcript.TranscriptEpoch, 10), record.sequence, eventID, record.eventDigest, receiptID); err != nil {
		return lifecycle.ErrUnavailable
	}
	for kind, digest := range map[string]string{"event": eventID, "receipt": receiptID} {
		if _, err := conn.ExecContext(ctx, `INSERT INTO lifecycle_identifier_tombstones
			(tenant_id, channel_id, identifier_kind, identifier_digest, operation_id) VALUES (?, ?, ?, ?, ?)`,
			transcript.TenantID, transcript.ChannelID, kind, digest, operationID); err != nil {
			return lifecycle.ErrUnavailable
		}
	}
	return nil
}

func validateRemovalEvidence(ctx context.Context, conn *sql.Conn, stored lifecycleOperationRow) bool {
	rows, err := conn.QueryContext(ctx, `SELECT server_sequence, event_id_digest, event_digest, receipt_id_digest
		FROM lifecycle_payload_tombstones WHERE operation_id = ? ORDER BY server_sequence`, stored.operation.Intent.OperationID)
	if err != nil {
		return false
	}
	defer rows.Close()
	var records []removalRecord
	for rows.Next() {
		var record removalRecord
		if rows.Scan(&record.sequence, &record.eventID, &record.eventDigest, &record.receiptID) != nil {
			return false
		}
		records = append(records, record)
	}
	return rows.Err() == nil && len(records) > 0 && removalDigest(records) == stored.payloadRemovalDigest
}

func removalDigest(records []removalRecord) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(removalDigestDomain))
	var sequence [8]byte
	for _, record := range records {
		binary.BigEndian.PutUint64(sequence[:], record.sequence)
		_, _ = hash.Write(sequence[:])
		for _, value := range []string{record.eventID, record.eventDigest, record.receiptID} {
			binary.BigEndian.PutUint64(sequence[:], uint64(len(value)))
			_, _ = hash.Write(sequence[:])
			_, _ = hash.Write([]byte(value))
		}
	}
	return "sha-256:" + hex.EncodeToString(hash.Sum(nil))
}

func identifierDigest(kind, value string) string {
	digest := sha256.Sum256([]byte(identifierDigestDomain + kind + "\x00" + value))
	return "sha-256:" + hex.EncodeToString(digest[:])
}

func closedFound(err error, found bool) error {
	if err != nil {
		return err
	}
	if !found {
		return lifecycle.ErrInvalidContract
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
