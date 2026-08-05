package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	policyDigestDomain             = "yukh.transcript-lifecycle-policy.v0.1\x00"
	intentDigestDomain             = "yukh.transcript-lifecycle-intent.v0.1\x00"
	markerDigestDomain             = "yukh.transcript-lifecycle-marker.v0.1\x00"
	receiptSignDomain              = "yukh.transcript-lifecycle-receipt.v0.1\x00"
	backupObligationDigestDomain   = "yukh.transcript-backup-obligation.v0.1\x00"
	custodianReceiptDigestDomain   = "yukh.transcript-backup-custodian-receipt.v0.1\x00"
	custodianReceiptSignDomain     = "yukh.transcript-backup-custodian-receipt-signature.v0.1\x00"
	completionEvidenceDigestDomain = "yukh.transcript-lifecycle-completion-evidence.v0.1\x00"
	backupRecoveryDigestDomain     = "yukh.transcript-lifecycle-backup-recovery.v0.1\x00"
)

var (
	ErrInvalidContract = errors.New("lifecycle: invalid contract")
	ErrConflict        = errors.New("lifecycle: operation conflict")
	ErrUnavailable     = errors.New("lifecycle: operation unavailable")
)

func CanonicalPolicy(policy Policy) ([]byte, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	return canonical(policy)
}

func CanonicalBackupObligation(value BackupObligation) ([]byte, string, error) {
	if ValidateBackupObligation(value) != nil {
		return nil, "", ErrInvalidContract
	}
	body, err := canonical(value)
	if err != nil {
		return nil, "", ErrInvalidContract
	}
	return body, digest(backupObligationDigestDomain, body), nil
}

func CanonicalCustodianReceipt(value CustodianReceipt) ([]byte, string, []byte, error) {
	if ValidateCustodianReceipt(value) != nil {
		return nil, "", nil, ErrInvalidContract
	}
	body, err := canonical(value)
	if err != nil {
		return nil, "", nil, ErrInvalidContract
	}
	unsigned := value
	unsigned.DetachedSignature = ""
	preimageBody, err := canonical(custodianReceiptUnsigned(unsigned))
	if err != nil {
		return nil, "", nil, ErrInvalidContract
	}
	signing := append([]byte(custodianReceiptSignDomain), preimageBody...)
	return body, digest(custodianReceiptDigestDomain, body), signing, nil
}

func CanonicalCompletionEvidence(value CompletionEvidence) ([]byte, string, error) {
	if ValidateCompletionEvidence(value) != nil {
		return nil, "", ErrInvalidContract
	}
	body, err := canonical(value)
	if err != nil {
		return nil, "", ErrInvalidContract
	}
	return body, digest(completionEvidenceDigestDomain, body), nil
}

func CanonicalBackupRecovery(value BackupRecovery) ([]byte, string, error) {
	if ValidateBackupRecovery(value) != nil {
		return nil, "", ErrInvalidContract
	}
	body, err := canonical(value)
	if err != nil {
		return nil, "", ErrInvalidContract
	}
	return body, digest(backupRecoveryDigestDomain, body), nil
}

type unsignedCustodianReceipt struct {
	Profile              string        `json:"profile"`
	ReceiptID            string        `json:"receipt_id"`
	ObligationDigest     string        `json:"obligation_digest"`
	OperationID          string        `json:"operation_id"`
	IntentDigest         string        `json:"intent_digest"`
	PolicyDigest         string        `json:"policy_digest"`
	Domain               BackupDomain  `json:"domain"`
	BackupIdentityDigest string        `json:"backup_identity_digest"`
	EvidenceTime         string        `json:"evidence_time"`
	Method               BackupMethod  `json:"method"`
	Outcome              BackupOutcome `json:"outcome"`
	CustodianReference   string        `json:"custodian_reference"`
	VerificationKeyID    string        `json:"verification_key_id"`
	SignatureAlgorithm   string        `json:"signature_algorithm"`
}

func custodianReceiptUnsigned(v CustodianReceipt) unsignedCustodianReceipt {
	return unsignedCustodianReceipt{v.Profile, v.ReceiptID, v.ObligationDigest, v.OperationID, v.IntentDigest, v.PolicyDigest, v.Domain, v.BackupIdentityDigest, v.EvidenceTime, v.Method, v.Outcome, v.CustodianReference, v.VerificationKeyID, v.SignatureAlgorithm}
}

func PolicyDigest(policy Policy) (string, error) {
	if !validPolicyFields(policy) {
		return "", ErrInvalidContract
	}
	body, err := canonical(policyUnsigned(policy))
	if err != nil {
		return "", ErrInvalidContract
	}
	return digest(policyDigestDomain, body), nil
}

func ValidatePolicySuccessor(current, next Policy) error {
	if ValidatePolicy(current) != nil || ValidatePolicy(next) != nil || next.PolicyEpoch <= current.PolicyEpoch || next.ActivatedAt <= current.ActivatedAt {
		return ErrConflict
	}
	return nil
}

func CanonicalIntent(intent Intent) ([]byte, string, error) {
	if err := ValidateIntent(intent); err != nil {
		return nil, "", err
	}
	body, err := canonical(intent)
	if err != nil {
		return nil, "", ErrInvalidContract
	}
	return body, digest(intentDigestDomain, body), nil
}

// ValidateRetry accepts only the exact original operation identity and
// canonical intent. It returns a closed conflict for any attempted replacement
// or target broadening.
func ValidateRetry(original, retry Intent) error {
	_, originalDigest, originalErr := CanonicalIntent(original)
	_, retryDigest, retryErr := CanonicalIntent(retry)
	if originalErr != nil || retryErr != nil {
		return ErrInvalidContract
	}
	if original.OperationID != retry.OperationID || originalDigest != retryDigest {
		return ErrConflict
	}
	return nil
}

func CanonicalMarker(marker Marker) ([]byte, string, error) {
	if err := ValidateMarker(marker); err != nil {
		return nil, "", err
	}
	body, err := canonical(marker)
	if err != nil {
		return nil, "", ErrInvalidContract
	}
	return body, digest(markerDigestDomain, body), nil
}

func CanonicalReceiptPreimage(receipt ReceiptPreimage) ([]byte, []byte, error) {
	if err := ValidateReceiptPreimage(receipt); err != nil {
		return nil, nil, err
	}
	body, err := canonical(receipt)
	if err != nil {
		return nil, nil, ErrInvalidContract
	}
	signing := make([]byte, 0, len(receiptSignDomain)+len(body))
	signing = append(signing, receiptSignDomain...)
	signing = append(signing, body...)
	return body, signing, nil
}

func ValidateCanonical(raw []byte) error {
	if len(raw) == 0 || len(raw) > 16_384 {
		return ErrInvalidContract
	}
	normalized, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(normalized, raw) {
		return ErrInvalidContract
	}
	return nil
}

func decodeCanonical(raw []byte, value any) error {
	if ValidateCanonical(raw) != nil {
		return ErrInvalidContract
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalidContract
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidContract
	}
	return nil
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func digest(domain string, body []byte) string {
	preimage := make([]byte, 0, len(domain)+len(body))
	preimage = append(preimage, domain...)
	preimage = append(preimage, body...)
	value := sha256.Sum256(preimage)
	return "sha-256:" + hex.EncodeToString(value[:])
}

type unsignedPolicy struct {
	Profile                      string     `json:"profile"`
	PolicyID                     string     `json:"policy_id"`
	PolicyEpoch                  uint64     `json:"policy_epoch"`
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

func policyUnsigned(value Policy) unsignedPolicy {
	return unsignedPolicy{
		Profile: value.Profile, PolicyID: value.PolicyID, PolicyEpoch: value.PolicyEpoch,
		ActiveRetentionMillis: value.ActiveRetentionMillis, EventBackupDeletionMillis: value.EventBackupDeletionMillis,
		IdentityBackupDeletionMillis: value.IdentityBackupDeletionMillis, SecurityAuditDeletionMillis: value.SecurityAuditDeletionMillis,
		ExportMode: value.ExportMode, RedactionAuthorityRoleID: value.RedactionAuthorityRoleID,
		DeletionAuthorityRoleID: value.DeletionAuthorityRoleID, IntegrityProfile: value.IntegrityProfile,
		IssuedAt: value.IssuedAt, ActivatedAt: value.ActivatedAt, AccountablePolicyApprover: value.AccountablePolicyApprover,
	}
}
