package lifecycle

import (
	"context"
	"encoding/base64"
	"errors"
)

type RecoveryStatus string

const (
	RecoveryPending     RecoveryStatus = "pending"
	RecoveryIncident    RecoveryStatus = "incident"
	RecoveryCorrupt     RecoveryStatus = "corrupt"
	RecoveryCompletable RecoveryStatus = "completable"
)

type RecoveryReason string

const (
	RecoveryEvidenceMissing         RecoveryReason = "evidence_missing"
	RecoveryReceiptFailed           RecoveryReason = "receipt_failed"
	RecoveryDeadlineMissed          RecoveryReason = "deadline_missed"
	RecoveryContradictoryEvidence   RecoveryReason = "contradictory_evidence"
	RecoveryInvalidEvidence         RecoveryReason = "invalid_evidence"
	RecoveryVerificationUnavailable RecoveryReason = "verification_unavailable"
)

type RecoveryFinding struct {
	Domain BackupDomain   `json:"domain"`
	Reason RecoveryReason `json:"reason"`
}

// BackupRecovery is deliberately bounded: it carries only closed state and
// custody domains, never provider responses, paths, accounts or payload.
type BackupRecovery struct {
	Profile      string            `json:"profile"`
	OperationID  string            `json:"operation_id"`
	IntentDigest string            `json:"intent_digest"`
	Status       RecoveryStatus    `json:"status"`
	Findings     []RecoveryFinding `json:"findings"`
}

func CloneBackupObligation(value BackupObligation) BackupObligation { return value }
func CloneCustodianReceipt(value CustodianReceipt) CustodianReceipt { return value }
func CloneCompletionEvidence(value CompletionEvidence) CompletionEvidence {
	value.Receipts = append([]ReceiptEvidence(nil), value.Receipts...)
	return value
}
func CloneBackupRecovery(value BackupRecovery) BackupRecovery {
	value.Findings = append([]RecoveryFinding(nil), value.Findings...)
	return value
}

func ValidateCustodianReceiptSignature(ctx context.Context, verifier CustodianReceiptVerifier, value CustodianReceipt) error {
	if verifier == nil {
		return ErrUnavailable
	}
	_, _, signing, err := CanonicalCustodianReceipt(value)
	if err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(value.DetachedSignature)
	if err := verifier.VerifyCustodianReceipt(ctx, value.VerificationKeyID, value.SignatureAlgorithm, signing, signature); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return ErrUnavailable
		}
		return ErrInvalidContract
	}
	return nil
}

func ValidateCustodianReceiptRetry(original, retry CustodianReceipt) error {
	_, originalDigest, _, originalErr := CanonicalCustodianReceipt(original)
	_, retryDigest, _, retryErr := CanonicalCustodianReceipt(retry)
	if originalErr != nil || retryErr != nil {
		return ErrInvalidContract
	}
	if original.ReceiptID != retry.ReceiptID || originalDigest != retryDigest {
		return ErrConflict
	}
	return nil
}

func ValidateCompletionRetry(original, retry CompletionEvidence) error {
	_, originalDigest, originalErr := CanonicalCompletionEvidence(original)
	_, retryDigest, retryErr := CanonicalCompletionEvidence(retry)
	if originalErr != nil || retryErr != nil {
		return ErrInvalidContract
	}
	if original.OperationID != retry.OperationID || originalDigest != retryDigest {
		return ErrConflict
	}
	return nil
}

// ClassifyBackupRecovery verifies every receipt before considering it. A
// failure, a late success or any second distinct receipt for one obligation is
// an incident forever. A later success is append-only evidence; it cannot
// resolve the incident or authorize completion without a future accepted
// incident-resolution contract.
func ClassifyBackupRecovery(ctx context.Context, reference OperationReference, obligations []BackupObligation, receipts []CustodianReceipt, verifier CustodianReceiptVerifier) BackupRecovery {
	want := []BackupDomain{EventBackupDomain, IdentityBackupDomain, AuditBackupDomain}
	result := func(status RecoveryStatus, findings []RecoveryFinding) BackupRecovery {
		return BackupRecovery{BackupRecoveryProfile, reference.OperationID, reference.IntentDigest, status, findings}
	}
	if ValidateOperationReference(reference) != nil || len(obligations) != 3 {
		return result(RecoveryCorrupt, nil)
	}
	digests := make(map[BackupDomain]string, 3)
	deadlines := make(map[BackupDomain]string, 3)
	for i, obligation := range obligations {
		_, digest, err := CanonicalBackupObligation(obligation)
		if err != nil || obligation.Domain != want[i] || obligation.OperationID != reference.OperationID || obligation.IntentDigest != reference.IntentDigest || i > 0 && obligation.PolicyDigest != obligations[0].PolicyDigest {
			return result(RecoveryCorrupt, nil)
		}
		digests[obligation.Domain], deadlines[obligation.Domain] = digest, obligation.Deadline
	}
	seen := make(map[BackupDomain]CustodianReceipt, 3)
	incidents := make(map[BackupDomain]RecoveryReason, 3)
	pending := make(map[BackupDomain]RecoveryReason, 3)
	receiptIDs := make(map[string]BackupDomain, len(receipts))
	for _, receipt := range receipts {
		if !validBackupDomain(receipt.Domain) {
			return result(RecoveryCorrupt, nil)
		}
		if domain, exists := receiptIDs[receipt.ReceiptID]; exists && domain != receipt.Domain {
			return result(RecoveryCorrupt, nil)
		}
		receiptIDs[receipt.ReceiptID] = receipt.Domain
		obligation := obligations[indexDomain(receipt.Domain)]
		if ValidateReceiptObligation(receipt, obligation, digests[receipt.Domain]) != nil {
			return result(RecoveryCorrupt, []RecoveryFinding{{receipt.Domain, RecoveryInvalidEvidence}})
		}
		if signatureErr := ValidateCustodianReceiptSignature(ctx, verifier, receipt); signatureErr != nil {
			if errors.Is(signatureErr, ErrUnavailable) {
				pending[receipt.Domain] = RecoveryVerificationUnavailable
				continue
			}
			return result(RecoveryCorrupt, []RecoveryFinding{{receipt.Domain, RecoveryInvalidEvidence}})
		}
		if previous, ok := seen[receipt.Domain]; ok {
			if ValidateCustodianReceiptRetry(previous, receipt) != nil {
				incidents[receipt.Domain] = RecoveryContradictoryEvidence
			}
			continue
		}
		seen[receipt.Domain] = receipt
		if receipt.Outcome == BackupFailed {
			incidents[receipt.Domain] = RecoveryReceiptFailed
		}
		if receipt.Outcome == BackupSucceeded && receipt.EvidenceTime > deadlines[receipt.Domain] {
			incidents[receipt.Domain] = RecoveryDeadlineMissed
		}
	}
	var findings []RecoveryFinding
	hasIncident := false
	for _, domain := range want {
		if reason, found := incidents[domain]; found {
			findings = append(findings, RecoveryFinding{domain, reason})
			hasIncident = true
			continue
		}
		if reason, found := pending[domain]; found {
			findings = append(findings, RecoveryFinding{domain, reason})
			continue
		}
		if _, ok := seen[domain]; !ok {
			findings = append(findings, RecoveryFinding{domain, RecoveryEvidenceMissing})
		}
	}
	if hasIncident {
		return result(RecoveryIncident, findings)
	}
	if len(findings) > 0 {
		return result(RecoveryPending, findings)
	}
	return result(RecoveryCompletable, []RecoveryFinding{})
}

func indexDomain(domain BackupDomain) int {
	switch domain {
	case EventBackupDomain:
		return 0
	case IdentityBackupDomain:
		return 1
	case AuditBackupDomain:
		return 2
	default:
		return 0
	}
}

func ValidateCompletionAgainst(ctx context.Context, evidence CompletionEvidence, obligations []BackupObligation, receipts []CustodianReceipt, verifier CustodianReceiptVerifier) error {
	if ValidateCompletionEvidence(evidence) != nil {
		return ErrInvalidContract
	}
	recovery := ClassifyBackupRecovery(ctx, OperationReference{evidence.OperationID, evidence.IntentDigest}, obligations, receipts, verifier)
	if recovery.Status != RecoveryCompletable {
		return ErrConflict
	}
	byDomain := make(map[BackupDomain]CustodianReceipt, 3)
	for _, receipt := range receipts {
		byDomain[receipt.Domain] = receipt
	}
	for _, reference := range evidence.Receipts {
		receipt := byDomain[reference.Domain]
		_, digest, _, err := CanonicalCustodianReceipt(receipt)
		if err != nil || receipt.ReceiptID != reference.ReceiptID || digest != reference.ReceiptDigest || receipt.OperationID != evidence.OperationID || receipt.IntentDigest != evidence.IntentDigest || receipt.PolicyDigest != evidence.PolicyDigest || evidence.CompletedAt < receipt.EvidenceTime {
			return ErrConflict
		}
	}
	return nil
}
