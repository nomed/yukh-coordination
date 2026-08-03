// Package audit owns canonical security-audit records and local chain receipts.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const (
	Profile             = "yukh-security-audit/v1"
	ReceiptProfile      = "yukh-security-audit-receipt/v1"
	MaxCanonicalBytes   = 4096
	MaxJSONSafeSequence = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidRecord = errors.New("invalid audit record")
	ErrConflict      = errors.New("audit operation conflict")
	ErrUnavailable   = errors.New("audit ledger unavailable")

	tenantPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,255}$`)
)

type canonicalRecord struct {
	Profile               string `json:"profile"`
	OperationID           string `json:"operation_id"`
	OperationKind         string `json:"operation_kind"`
	Outcome               string `json:"outcome"`
	Reason                string `json:"reason"`
	DecisionTime          string `json:"decision_time"`
	TenantID              string `json:"tenant_id,omitempty"`
	PrincipalID           string `json:"principal_id,omitempty"`
	ParticipantInstanceID string `json:"participant_instance_id,omitempty"`
	SessionEpoch          uint64 `json:"session_epoch,omitempty"`
	DPoPThumbprintDigest  string `json:"dpop_thumbprint_digest,omitempty"`
}

type Receipt struct {
	Profile             string `json:"profile"`
	LedgerID            string `json:"ledger_id"`
	Sequence            uint64 `json:"sequence"`
	OperationID         string `json:"operation_id"`
	RecordDigest        string `json:"record_digest"`
	PreviousChainDigest string `json:"previous_chain_digest"`
	ChainDigest         string `json:"chain_digest"`
}

func CanonicalRecord(record identity.AuditRecord) ([]byte, error) {
	if !validRecord(record) {
		return nil, ErrInvalidRecord
	}
	value := canonicalRecord{
		Profile: Profile, OperationID: record.OperationID, OperationKind: string(record.Operation),
		Outcome: string(record.Outcome), Reason: string(record.Reason),
		DecisionTime: record.DecisionTime.Format("2006-01-02T15:04:05.000Z"),
		TenantID:     record.TenantID, PrincipalID: record.PrincipalID,
		ParticipantInstanceID: record.ParticipantInstanceID, SessionEpoch: record.SessionEpoch,
	}
	if record.HasDPoPThumbprint {
		value.DPoPThumbprintDigest = encodeDigest(record.DPoPThumbprint)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidRecord
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > MaxCanonicalBytes {
		return nil, ErrInvalidRecord
	}
	return canonical, nil
}

// ValidateCanonicalRecord proves both the exact JCS representation and the
// closed operation-specific record shape. It never repairs stored evidence.
func ValidateCanonicalRecord(canonical []byte) error {
	if len(canonical) == 0 || len(canonical) > MaxCanonicalBytes {
		return ErrInvalidRecord
	}
	normalized, err := jsoncanonicalizer.Transform(canonical)
	if err != nil || !bytes.Equal(normalized, canonical) {
		return ErrInvalidRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var value canonicalRecord
	if err := decoder.Decode(&value); err != nil {
		return ErrInvalidRecord
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRecord
	}
	if value.Profile != Profile {
		return ErrInvalidRecord
	}
	decisionTime, err := time.Parse("2006-01-02T15:04:05.000Z", value.DecisionTime)
	if err != nil || decisionTime.Format("2006-01-02T15:04:05.000Z") != value.DecisionTime {
		return ErrInvalidRecord
	}
	record := identity.AuditRecord{
		ProfileVersion: 1, OperationID: value.OperationID,
		Operation: identity.AuditOperation(value.OperationKind), Outcome: identity.AuditOutcome(value.Outcome),
		Reason: identity.AuditReason(value.Reason), DecisionTime: decisionTime,
		TenantID: value.TenantID, PrincipalID: value.PrincipalID,
		ParticipantInstanceID: value.ParticipantInstanceID, SessionEpoch: value.SessionEpoch,
	}
	if value.DPoPThumbprintDigest != "" {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value.DPoPThumbprintDigest)
		if err != nil || len(decoded) != sha256.Size {
			return ErrInvalidRecord
		}
		copy(record.DPoPThumbprint[:], decoded)
		record.HasDPoPThumbprint = true
	}
	if !validRecord(record) {
		return ErrInvalidRecord
	}
	reencoded, err := CanonicalRecord(record)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return ErrInvalidRecord
	}
	return nil
}

func CanonicalReceipt(receipt Receipt) ([]byte, error) {
	if !validReceipt(receipt) {
		return nil, ErrUnavailable
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, ErrUnavailable
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, ErrUnavailable
	}
	return canonical, nil
}

func RecordDigest(canonical []byte) [sha256.Size]byte {
	preimage := make([]byte, 0, len(canonical)+48)
	preimage = append(preimage, "yukh-coordination:audit-record:v1\n"...)
	preimage = append(preimage, canonical...)
	return sha256.Sum256(preimage)
}

func GenesisDigest(ledgerID string) ([sha256.Size]byte, error) {
	id, err := canonicalV7(ledgerID)
	if err != nil {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	preimage := make([]byte, 0, 80)
	preimage = append(preimage, "yukh-coordination:audit-chain-genesis:v1\n"...)
	preimage = append(preimage, id[:]...)
	return sha256.Sum256(preimage), nil
}

func ChainDigest(sequence uint64, previous, record [sha256.Size]byte) ([sha256.Size]byte, error) {
	if sequence == 0 || sequence > MaxJSONSafeSequence {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	preimage := make([]byte, 0, 120)
	preimage = append(preimage, "yukh-coordination:audit-chain:v1\n"...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	preimage = append(preimage, encoded[:]...)
	preimage = append(preimage, previous[:]...)
	preimage = append(preimage, record[:]...)
	return sha256.Sum256(preimage), nil
}

func NewReceipt(ledgerID string, sequence uint64, operationID string, record, previous, chain [sha256.Size]byte) (Receipt, error) {
	if _, err := canonicalV7(ledgerID); err != nil {
		return Receipt{}, ErrUnavailable
	}
	if _, err := canonicalV7(operationID); err != nil || sequence == 0 || sequence > MaxJSONSafeSequence {
		return Receipt{}, ErrUnavailable
	}
	return Receipt{Profile: ReceiptProfile, LedgerID: ledgerID, Sequence: sequence, OperationID: operationID,
		RecordDigest: encodeDigest(record), PreviousChainDigest: encodeDigest(previous), ChainDigest: encodeDigest(chain)}, nil
}

func (r Receipt) Reference() string {
	return fmt.Sprintf("audit:%s:%d:%s", r.LedgerID, r.Sequence, r.ChainDigest)
}

func validRecord(record identity.AuditRecord) bool {
	if record.ProfileVersion != 1 || record.DecisionTime.Location() != time.UTC || !record.DecisionTime.Equal(record.DecisionTime.Truncate(time.Millisecond)) {
		return false
	}
	if _, err := canonicalV7(record.OperationID); err != nil {
		return false
	}
	if record.Operation != identity.AuditBootstrap && record.Operation != identity.AuditAuthentication {
		return false
	}
	switch record.Outcome {
	case identity.AuditAllow:
		if record.Reason != identity.AuditReasonAllowed || !validIdentity(record, true) || !record.HasDPoPThumbprint {
			return false
		}
	case identity.AuditDeny:
		if record.Reason != identity.AuditReasonInvalidCredential && record.Reason != identity.AuditReasonProofReplay && record.Reason != identity.AuditReasonInactiveSession {
			return false
		}
		if !validIdentity(record, false) {
			return false
		}
	case identity.AuditUnavailable:
		if record.Reason != identity.AuditReasonVerificationUnavailable && record.Reason != identity.AuditReasonRegistryUnavailable && record.Reason != identity.AuditReasonMaterialCollision {
			return false
		}
		if !validIdentity(record, false) {
			return false
		}
	default:
		return false
	}
	return record.HasDPoPThumbprint || record.DPoPThumbprint == ([sha256.Size]byte{})
}

func validIdentity(record identity.AuditRecord, required bool) bool {
	hasTenant := record.TenantID != "" || record.PrincipalID != ""
	if hasTenant && (!tenantPattern.MatchString(record.TenantID) || !validDigestText(record.PrincipalID)) {
		return false
	}
	hasSession := record.ParticipantInstanceID != "" || record.SessionEpoch != 0
	if hasSession {
		if _, err := canonicalV7(record.ParticipantInstanceID); err != nil || record.SessionEpoch == 0 || record.SessionEpoch > MaxJSONSafeSequence || !hasTenant {
			return false
		}
	}
	return !required || (hasTenant && hasSession)
}

func validReceipt(receipt Receipt) bool {
	if receipt.Profile != ReceiptProfile || receipt.Sequence == 0 || receipt.Sequence > MaxJSONSafeSequence {
		return false
	}
	if _, err := canonicalV7(receipt.LedgerID); err != nil {
		return false
	}
	if _, err := canonicalV7(receipt.OperationID); err != nil {
		return false
	}
	return validDigestText(receipt.RecordDigest) && validDigestText(receipt.PreviousChainDigest) && validDigestText(receipt.ChainDigest)
}

func canonicalV7(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id.Version() != 7 || id.String() != value {
		return uuid.Nil, ErrInvalidRecord
	}
	return id, nil
}

func validDigestText(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(value) == 43 && len(decoded) == sha256.Size
}

func encodeDigest(value [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(value[:])
}
