// Package lifecycle defines the authority-neutral RFC-0023 transcript
// lifecycle contract. It deliberately contains no persistence or destructive
// implementation.
package lifecycle

import (
	"bytes"
	"context"
)

const (
	PolicyProfile  = "yukh-transcript-lifecycle-policy/v0.1"
	IntentProfile  = "yukh-transcript-lifecycle-intent/v0.1"
	MarkerProfile  = "yukh-transcript-lifecycle-marker/v0.1"
	ReceiptProfile = "yukh-transcript-lifecycle-receipt-preimage/v0.1"

	IntegrityProfileV1 = "sequence-event-receipt-operation/v0.1"
	MaxSafeInteger     = uint64(9_007_199_254_740_991)
)

type Lifecycle string

const (
	Active   Lifecycle = "active"
	Redacted Lifecycle = "redacted"
	Deleted  Lifecycle = "deleted"
)

type SagaState string

const (
	Reserved        SagaState = "reserved"
	ExportSatisfied SagaState = "export_satisfied"
	MarkerPersisted SagaState = "marker_persisted"
	ReceiptSigned   SagaState = "receipt_signed"
	PayloadRemoved  SagaState = "payload_removed"
	BackupsPending  SagaState = "backups_pending"
	Completed       SagaState = "completed"
)

type Action string

const (
	RedactTranscript Action = "redact"
	DeleteTranscript Action = "delete"
)

type Reason string

const (
	ReasonRetentionExpired  Reason = "retention_expired"
	ReasonAuthorizedRequest Reason = "authorized_request"
)

type ExportMode string

const (
	ExportForbidden ExportMode = "forbidden"
	ExportPermitted ExportMode = "permitted"
	ExportRequired  ExportMode = "required"
)

type TargetKind string

const (
	TargetSequences  TargetKind = "sequences"
	TargetTranscript TargetKind = "transcript"
)

type BackupDomain string

const (
	EventBackupDomain    BackupDomain = "event"
	IdentityBackupDomain BackupDomain = "identity"
	AuditBackupDomain    BackupDomain = "security_audit"
)

type AuditReason string

const (
	AuditPolicyActivated  AuditReason = "policy_activated"
	AuditReserved         AuditReason = "lifecycle_reserved"
	AuditExportVerified   AuditReason = "export_verified"
	AuditMarkerPersisted  AuditReason = "marker_persisted"
	AuditReceiptSigned    AuditReason = "receipt_signed"
	AuditPayloadRemoved   AuditReason = "payload_removed"
	AuditBackupRecorded   AuditReason = "backup_receipt_recorded"
	AuditCompleted        AuditReason = "lifecycle_completed"
	AuditDeadlineMissed   AuditReason = "backup_deadline_missed"
	AuditClockFenced      AuditReason = "clock_fenced"
	AuditRestoreVerified  AuditReason = "restore_verified"
	AuditIncidentRecorded AuditReason = "incident_recorded"
)

type TranscriptKey struct {
	TenantID        string `json:"tenant_id"`
	ChannelID       string `json:"channel_id"`
	TranscriptEpoch uint64 `json:"transcript_epoch"`
}

type Policy struct {
	Profile                      string     `json:"profile"`
	PolicyID                     string     `json:"policy_id"`
	PolicyEpoch                  uint64     `json:"policy_epoch"`
	PolicyDigest                 string     `json:"policy_digest"`
	ActiveRetentionMillis        uint64     `json:"active_retention_millis"`
	EventBackupDeletionMillis    uint64     `json:"event_backup_deletion_millis"`
	IdentityBackupDeletionMillis uint64     `json:"identity_backup_deletion_millis"`
	SecurityAuditDeletionMillis  uint64     `json:"security_audit_backup_deletion_millis"`
	ExportMode                   ExportMode `json:"export_mode"`
	RedactionAuthorityRoleID     string     `json:"redaction_authority_role_id"`
	DeletionAuthorityRoleID      string     `json:"deletion_authority_role_id"`
	IntegrityProfile             string     `json:"integrity_profile"`
	IssuedAt                     string     `json:"issued_at"`
	ActivatedAt                  string     `json:"activated_at"`
	AccountablePolicyApprover    string     `json:"accountable_policy_approver"`
}

type Target struct {
	Kind      TargetKind `json:"kind"`
	Sequences []uint64   `json:"sequences,omitempty"`
}

type BackupDeadline struct {
	Domain   BackupDomain `json:"domain"`
	Deadline string       `json:"deadline"`
}

type Intent struct {
	Profile                       string           `json:"profile"`
	OperationID                   string           `json:"operation_id"`
	Transcript                    TranscriptKey    `json:"transcript"`
	Action                        Action           `json:"action"`
	Reason                        Reason           `json:"reason"`
	PolicyID                      string           `json:"policy_id"`
	PolicyEpoch                   uint64           `json:"policy_epoch"`
	PolicyDigest                  string           `json:"policy_digest"`
	Target                        Target           `json:"target"`
	HighWaterReceiptReference     string           `json:"high_water_receipt_reference"`
	RequestedAt                   string           `json:"requested_at"`
	RequesterRoleID               string           `json:"requester_role_id"`
	AuthorizingAuditReceipt       string           `json:"authorizing_audit_receipt"`
	ExportMode                    ExportMode       `json:"export_mode"`
	ExpectedBackupDeletionWindows []BackupDeadline `json:"expected_backup_deletion_deadlines"`
}

type Marker struct {
	Profile                   string        `json:"profile"`
	OperationID               string        `json:"operation_id"`
	IntentDigest              string        `json:"intent_digest"`
	Transcript                TranscriptKey `json:"transcript"`
	PreviousLifecycle         Lifecycle     `json:"previous_lifecycle"`
	ResultingLifecycle        Lifecycle     `json:"resulting_lifecycle"`
	Target                    Target        `json:"target"`
	PolicyDigest              string        `json:"policy_digest"`
	HighWaterReceiptReference string        `json:"high_water_receipt_reference"`
	MarkerTime                string        `json:"marker_time"`
	AuthorizingAuditReceipt   string        `json:"authorizing_audit_receipt"`
}

type ReceiptPreimage struct {
	Profile            string        `json:"profile"`
	ReceiptID          string        `json:"receipt_id"`
	MarkerDigest       string        `json:"marker_digest"`
	OperationID        string        `json:"operation_id"`
	IntentDigest       string        `json:"intent_digest"`
	Transcript         TranscriptKey `json:"transcript"`
	ResultingLifecycle Lifecycle     `json:"resulting_lifecycle"`
	PolicyDigest       string        `json:"policy_digest"`
	IssuedAt           string        `json:"issued_at"`
	SigningKeyID       string        `json:"signing_key_id"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
}

type Operation struct {
	Intent       Intent
	IntentDigest string
	State        SagaState
	Marker       []byte
	Receipt      []byte
	Signature    []byte
}

// CloneOperation returns a deep copy suitable for crossing the administrative
// port. Store implementations must not share mutable byte or slice storage
// with callers.
func CloneOperation(value Operation) Operation {
	value.Intent.Target.Sequences = append([]uint64(nil), value.Intent.Target.Sequences...)
	value.Intent.ExpectedBackupDeletionWindows = append([]BackupDeadline(nil), value.Intent.ExpectedBackupDeletionWindows...)
	value.Marker = bytes.Clone(value.Marker)
	value.Receipt = bytes.Clone(value.Receipt)
	value.Signature = bytes.Clone(value.Signature)
	return value
}

type OperationReference struct {
	OperationID  string
	IntentDigest string
}

type DueQuery struct {
	WallTime         string
	AfterOperationID string
	Limit            uint16
}

type ExportEvidence struct {
	OperationID          string
	IntentDigest         string
	ManifestDigest       string
	CustodyReceiptDigest string
}

type MarkerPersistence struct {
	OperationID       string
	IntentDigest      string
	CanonicalMarker   []byte
	CanonicalPreimage []byte
}

type SignatureAttachment struct {
	OperationID     string
	IntentDigest    string
	ReceiptPreimage []byte
	Signature       []byte
}

type BackupReceipt struct {
	OperationID   string
	IntentDigest  string
	Domain        BackupDomain
	ReceiptDigest string
}

// TranscriptLifecyclePreparationStore is the non-destructive administrative
// capability. It can reserve and fence work, but cannot sign or remove data.
type TranscriptLifecyclePreparationStore interface {
	InspectDue(context.Context, DueQuery) ([]Operation, error)
	Reserve(context.Context, Intent) (Operation, error)
	BindExport(context.Context, ExportEvidence) (Operation, error)
	PersistMarker(context.Context, MarkerPersistence) (Operation, error)
	Inspect(context.Context, string) (Operation, error)
}

// TranscriptLifecycleCompletionStore contains the separately gated
// destructive and external-custody capabilities.
type TranscriptLifecycleCompletionStore interface {
	AttachSignature(context.Context, SignatureAttachment) (Operation, error)
	RemovePayload(context.Context, OperationReference) (Operation, error)
	RecordBackupReceipt(context.Context, BackupReceipt) (Operation, error)
	Complete(context.Context, OperationReference) (Operation, error)
}

// TranscriptLifecycleStore is the complete administrative capability. It is
// not embedded in or type-compatible with the ordinary relay.Store port.
type TranscriptLifecycleStore interface {
	TranscriptLifecyclePreparationStore
	TranscriptLifecycleCompletionStore
}
