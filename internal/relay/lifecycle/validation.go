package lifecycle

import (
	"encoding/base64"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,255}$`)
	digestPattern     = regexp.MustCompile(`^sha-256:[0-9a-f]{64}$`)
	referencePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$`)
)

func ValidatePolicy(policy Policy) error {
	if !validPolicyFields(policy) || !digestPattern.MatchString(policy.PolicyDigest) {
		return ErrInvalidContract
	}
	want, err := PolicyDigest(policy)
	if err != nil || policy.PolicyDigest != want {
		return ErrInvalidContract
	}
	return nil
}

func validPolicyFields(policy Policy) bool {
	return policy.Profile == PolicyProfile && validIdentifier(policy.PolicyID) && positive(policy.PolicyEpoch) &&
		positive(policy.ActiveRetentionMillis) && positive(policy.EventBackupDeletionMillis) &&
		positive(policy.IdentityBackupDeletionMillis) && positive(policy.SecurityAuditDeletionMillis) &&
		validExport(policy.ExportMode) && validIdentifier(policy.RedactionAuthorityRoleID) &&
		validIdentifier(policy.DeletionAuthorityRoleID) && policy.RedactionAuthorityRoleID != policy.DeletionAuthorityRoleID &&
		policy.IntegrityProfile == IntegrityProfileV1 && validTime(policy.IssuedAt) && validTime(policy.ActivatedAt) &&
		policy.ActivatedAt >= policy.IssuedAt && validIdentifier(policy.AccountablePolicyApprover)
}

func ValidateIntent(intent Intent) error {
	if intent.Profile != IntentProfile || !validUUIDv7(intent.OperationID) || !validTranscript(intent.Transcript) ||
		!validAction(intent.Action) || !validReason(intent.Reason) || !validIdentifier(intent.PolicyID) ||
		!positive(intent.PolicyEpoch) || !digestPattern.MatchString(intent.PolicyDigest) || !validTarget(intent.Action, intent.Target) ||
		!validReference(intent.HighWaterReceiptReference) || !validTime(intent.RequestedAt) || !validIdentifier(intent.RequesterRoleID) ||
		!validReference(intent.AuthorizingAuditReceipt) || !validExport(intent.ExportMode) || !validDeadlines(intent.ExpectedBackupDeletionWindows, intent.RequestedAt) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateMarker(marker Marker) error {
	if marker.Profile != MarkerProfile || !validUUIDv7(marker.OperationID) || !digestPattern.MatchString(marker.IntentDigest) ||
		!validTranscript(marker.Transcript) || !validTransition(marker.PreviousLifecycle, marker.ResultingLifecycle) ||
		!validTarget(actionForLifecycle(marker.ResultingLifecycle), marker.Target) || !digestPattern.MatchString(marker.PolicyDigest) ||
		!validReference(marker.HighWaterReceiptReference) || !validTime(marker.MarkerTime) || !validReference(marker.AuthorizingAuditReceipt) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateReceiptPreimage(receipt ReceiptPreimage) error {
	if receipt.Profile != ReceiptProfile || !validUUIDv7(receipt.ReceiptID) || !digestPattern.MatchString(receipt.MarkerDigest) ||
		!validUUIDv7(receipt.OperationID) || !digestPattern.MatchString(receipt.IntentDigest) || !validTranscript(receipt.Transcript) ||
		(receipt.ResultingLifecycle != Redacted && receipt.ResultingLifecycle != Deleted) || !digestPattern.MatchString(receipt.PolicyDigest) ||
		!validTime(receipt.IssuedAt) || !validIdentifier(receipt.SigningKeyID) || receipt.SignatureAlgorithm != "ed25519" {
		return ErrInvalidContract
	}
	return nil
}

func ValidSagaAdvance(from, to SagaState) bool {
	order := map[SagaState]int{Reserved: 0, ExportSatisfied: 1, MarkerPersisted: 2, ReceiptSigned: 3, PayloadRemoved: 4, BackupsPending: 5, Completed: 6}
	left, leftOK := order[from]
	right, rightOK := order[to]
	return leftOK && rightOK && right == left+1
}

func ValidAuditReason(value AuditReason) bool {
	switch value {
	case AuditPolicyActivated, AuditReserved, AuditExportVerified, AuditMarkerPersisted,
		AuditReceiptSigned, AuditPayloadRemoved, AuditBackupRecorded, AuditCompleted,
		AuditDeadlineMissed, AuditClockFenced, AuditRestoreVerified, AuditIncidentRecorded:
		return true
	default:
		return false
	}
}

func ValidateOperationReference(value OperationReference) error {
	if !validUUIDv7(value.OperationID) || !digestPattern.MatchString(value.IntentDigest) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateDueQuery(value DueQuery) error {
	if !validTime(value.WallTime) || value.Limit == 0 || value.Limit > 1000 || (value.AfterOperationID != "" && !validUUIDv7(value.AfterOperationID)) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateExportEvidence(value ExportEvidence) error {
	if ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil || !digestPattern.MatchString(value.ManifestDigest) || !digestPattern.MatchString(value.CustodyReceiptDigest) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateMarkerPersistence(value MarkerPersistence) error {
	if ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil {
		return ErrInvalidContract
	}
	var marker Marker
	var receipt ReceiptPreimage
	if decodeCanonical(value.CanonicalMarker, &marker) != nil || decodeCanonical(value.CanonicalPreimage, &receipt) != nil || ValidateMarker(marker) != nil || ValidateReceiptPreimage(receipt) != nil {
		return ErrInvalidContract
	}
	_, markerDigest, err := CanonicalMarker(marker)
	if err != nil || marker.OperationID != value.OperationID || marker.IntentDigest != value.IntentDigest ||
		receipt.OperationID != value.OperationID || receipt.IntentDigest != value.IntentDigest || receipt.MarkerDigest != markerDigest ||
		receipt.Transcript != marker.Transcript || receipt.ResultingLifecycle != marker.ResultingLifecycle || receipt.PolicyDigest != marker.PolicyDigest {
		return ErrConflict
	}
	return nil
}

func ValidateSignatureAttachment(value SignatureAttachment) error {
	if ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil || len(value.Signature) != 64 {
		return ErrInvalidContract
	}
	var receipt ReceiptPreimage
	if decodeCanonical(value.ReceiptPreimage, &receipt) != nil || ValidateReceiptPreimage(receipt) != nil {
		return ErrInvalidContract
	}
	if receipt.OperationID != value.OperationID || receipt.IntentDigest != value.IntentDigest {
		return ErrConflict
	}
	return nil
}

func ValidateBackupObligation(value BackupObligation) error {
	if value.Profile != BackupObligationProfile || ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil ||
		!digestPattern.MatchString(value.PolicyDigest) || !validBackupDomain(value.Domain) || !validTime(value.Deadline) ||
		(value.BindingKind != BackupGeneration && value.BindingKind != AbsenceManifest) || !digestPattern.MatchString(value.BindingDigest) {
		return ErrInvalidContract
	}
	return nil
}

func ValidateCustodianReceipt(value CustodianReceipt) error {
	signature, err := base64.RawURLEncoding.DecodeString(value.DetachedSignature)
	if value.Profile != CustodianReceiptProfile || !validUUIDv7(value.ReceiptID) || !digestPattern.MatchString(value.ObligationDigest) ||
		ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil || !digestPattern.MatchString(value.PolicyDigest) ||
		!validBackupDomain(value.Domain) || !digestPattern.MatchString(value.BackupIdentityDigest) || !validTime(value.EvidenceTime) ||
		(value.Method != GenerationRetired && value.Method != AbsenceProved) || (value.Outcome != BackupSucceeded && value.Outcome != BackupFailed) ||
		!validReference(value.CustodianReference) || !validIdentifier(value.VerificationKeyID) || value.SignatureAlgorithm != "ed25519" || err != nil || len(signature) != 64 {
		return ErrInvalidContract
	}
	return nil
}

func ValidateCompletionEvidence(value CompletionEvidence) error {
	if value.Profile != CompletionEvidenceProfile || ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil ||
		!digestPattern.MatchString(value.PolicyDigest) || len(value.Receipts) != 3 || !validReference(value.SecurityAuditReceipt) ||
		!validReference(value.SecurityAuditCheckpoint) || !validTime(value.CompletedAt) {
		return ErrInvalidContract
	}
	want := []BackupDomain{EventBackupDomain, IdentityBackupDomain, AuditBackupDomain}
	for i, receipt := range value.Receipts {
		if receipt.Domain != want[i] || !validUUIDv7(receipt.ReceiptID) || !digestPattern.MatchString(receipt.ReceiptDigest) {
			return ErrInvalidContract
		}
	}
	return nil
}

func ValidateBackupRecovery(value BackupRecovery) error {
	if value.Profile != BackupRecoveryProfile || ValidateOperationReference(OperationReference{value.OperationID, value.IntentDigest}) != nil {
		return ErrInvalidContract
	}
	validStatus := value.Status == RecoveryPending || value.Status == RecoveryIncident || value.Status == RecoveryCorrupt || value.Status == RecoveryCompletable
	validReason := value.Reason == RecoveryEvidenceMissing || value.Reason == RecoveryReceiptFailed || value.Reason == RecoveryDeadlineMissed || value.Reason == RecoveryContradictoryEvidence || value.Reason == RecoveryInvalidEvidence || value.Reason == RecoveryAllSatisfied
	if !validStatus || !validReason || len(value.Domains) > 3 {
		return ErrInvalidContract
	}
	last := -1
	for _, domain := range value.Domains {
		index := indexDomain(domain)
		if !validBackupDomain(domain) || index <= last {
			return ErrInvalidContract
		}
		last = index
	}
	if value.Status == RecoveryCompletable && (value.Reason != RecoveryAllSatisfied || len(value.Domains) != 0) || value.Status != RecoveryCompletable && value.Reason == RecoveryAllSatisfied {
		return ErrInvalidContract
	}
	if value.Status == RecoveryPending && (value.Reason != RecoveryEvidenceMissing || len(value.Domains) == 0) ||
		value.Status == RecoveryIncident && (value.Reason != RecoveryReceiptFailed && value.Reason != RecoveryDeadlineMissed && value.Reason != RecoveryContradictoryEvidence || len(value.Domains) == 0) ||
		value.Status == RecoveryCorrupt && value.Reason != RecoveryInvalidEvidence && value.Reason != RecoveryContradictoryEvidence {
		return ErrInvalidContract
	}
	return nil
}

func ValidateObligationIntent(value BackupObligation, intent Intent, intentDigest string) error {
	if ValidateBackupObligation(value) != nil || ValidateIntent(intent) != nil {
		return ErrInvalidContract
	}
	if value.OperationID != intent.OperationID || value.IntentDigest != intentDigest || value.PolicyDigest != intent.PolicyDigest {
		return ErrConflict
	}
	for _, deadline := range intent.ExpectedBackupDeletionWindows {
		if deadline.Domain == value.Domain && deadline.Deadline == value.Deadline {
			return nil
		}
	}
	return ErrConflict
}

func ValidateReceiptObligation(value CustodianReceipt, obligation BackupObligation, obligationDigest string) error {
	if ValidateCustodianReceipt(value) != nil || ValidateBackupObligation(obligation) != nil {
		return ErrInvalidContract
	}
	if value.ObligationDigest != obligationDigest || value.OperationID != obligation.OperationID || value.IntentDigest != obligation.IntentDigest || value.PolicyDigest != obligation.PolicyDigest || value.Domain != obligation.Domain || value.BackupIdentityDigest != obligation.BindingDigest {
		return ErrConflict
	}
	if obligation.BindingKind == BackupGeneration && value.Method != GenerationRetired || obligation.BindingKind == AbsenceManifest && value.Method != AbsenceProved {
		return ErrConflict
	}
	return nil
}

func validBackupDomain(value BackupDomain) bool {
	return value == EventBackupDomain || value == IdentityBackupDomain || value == AuditBackupDomain
}

func validTarget(action Action, target Target) bool {
	if action == DeleteTranscript {
		return target.Kind == TargetTranscript && len(target.Sequences) == 0
	}
	if action != RedactTranscript || target.Kind != TargetSequences || len(target.Sequences) == 0 || len(target.Sequences) > 1000 {
		return false
	}
	if !sort.SliceIsSorted(target.Sequences, func(i, j int) bool { return target.Sequences[i] < target.Sequences[j] }) {
		return false
	}
	for index, sequence := range target.Sequences {
		if !positive(sequence) || (index > 0 && sequence == target.Sequences[index-1]) {
			return false
		}
	}
	return true
}

func validDeadlines(values []BackupDeadline, requested string) bool {
	if len(values) != 3 {
		return false
	}
	want := []BackupDomain{EventBackupDomain, IdentityBackupDomain, AuditBackupDomain}
	requestedAt, _ := time.Parse("2006-01-02T15:04:05.000Z", requested)
	for index, value := range values {
		deadline, err := time.Parse("2006-01-02T15:04:05.000Z", value.Deadline)
		if value.Domain != want[index] || err != nil || !deadline.After(requestedAt) {
			return false
		}
	}
	return true
}

func validTransition(from, to Lifecycle) bool {
	return from == Active && (to == Redacted || to == Deleted) || from == Redacted && to == Deleted
}

func actionForLifecycle(value Lifecycle) Action {
	if value == Deleted {
		return DeleteTranscript
	}
	return RedactTranscript
}

func validTranscript(value TranscriptKey) bool {
	return validIdentifier(value.TenantID) && validIdentifier(value.ChannelID) && value.TranscriptEpoch <= MaxSafeInteger
}

func validUUIDv7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.Version() == 7 && parsed.String() == value
}

func validTime(value string) bool {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil && parsed.Format("2006-01-02T15:04:05.000Z") == value
}

func positive(value uint64) bool        { return value > 0 && value <= MaxSafeInteger }
func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func validReference(value string) bool  { return referencePattern.MatchString(value) }
func validExport(value ExportMode) bool {
	return value == ExportForbidden || value == ExportPermitted || value == ExportRequired
}
func validAction(value Action) bool { return value == RedactTranscript || value == DeleteTranscript }
func validReason(value Reason) bool {
	return value == ReasonRetentionExpired || value == ReasonAuthorizedRequest
}
