package lifecycle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type acceptingCustodianVerifier struct{}

func (acceptingCustodianVerifier) VerifyCustodianReceipt(_ context.Context, key, algorithm string, preimage, signature []byte) error {
	if key != "backup-key-1" || algorithm != "ed25519" || len(preimage) == 0 || len(signature) != 64 {
		return ErrInvalidContract
	}
	return nil
}

type backupVectors struct {
	Obligation             string `json:"obligation"`
	ObligationDigest       string `json:"obligation_digest"`
	CustodianReceipt       string `json:"custodian_receipt"`
	CustodianReceiptDigest string `json:"custodian_receipt_digest"`
	CompletionEvidence     string `json:"completion_evidence"`
	Recovery               string `json:"recovery"`
}

func TestCanonicalBackupCompletionVectors(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "test-vectors", "transcript-backup-completion-0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors backupVectors
	if json.Unmarshal(body, &vectors) != nil {
		t.Fatal("invalid vectors")
	}
	var obligation BackupObligation
	var receipt CustodianReceipt
	var completion CompletionEvidence
	var recovery BackupRecovery
	_ = json.Unmarshal([]byte(vectors.Obligation), &obligation)
	_ = json.Unmarshal([]byte(vectors.CustodianReceipt), &receipt)
	_ = json.Unmarshal([]byte(vectors.CompletionEvidence), &completion)
	_ = json.Unmarshal([]byte(vectors.Recovery), &recovery)
	canonical, digest, err := CanonicalBackupObligation(obligation)
	if err != nil || string(canonical) != vectors.Obligation || digest != vectors.ObligationDigest {
		t.Fatalf("obligation vector mismatch: %v %s %s", err, digest, canonical)
	}
	canonical, digest, signing, err := CanonicalCustodianReceipt(receipt)
	if err != nil || string(canonical) != vectors.CustodianReceipt || digest != vectors.CustodianReceiptDigest || string(signing[:len(custodianReceiptSignDomain)]) != custodianReceiptSignDomain {
		t.Fatalf("receipt vector mismatch: %v %s", err, digest)
	}
	if _, _, err := CanonicalCompletionEvidence(completion); err != nil {
		t.Fatal(err)
	}
	if canonical, _, err := CanonicalBackupRecovery(recovery); err != nil || string(canonical) != vectors.Recovery {
		t.Fatalf("recovery vector mismatch: %v", err)
	}
	if err := ValidateCustodianReceiptSignature(context.Background(), acceptingCustodianVerifier{}, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRequiresThreeTimelyVerifiedSuccesses(t *testing.T) {
	obligations, receipts := backupFixture(t)
	ctx := context.Background()
	verifier := acceptingCustodianVerifier{}
	reference := OperationReference{obligations[0].OperationID, obligations[0].IntentDigest}
	if got := ClassifyBackupRecovery(ctx, reference, obligations, receipts[:2], verifier); got.Status != RecoveryPending || len(got.Domains) != 1 || got.Domains[0] != AuditBackupDomain {
		t.Fatalf("pending = %#v", got)
	}
	if got := ClassifyBackupRecovery(ctx, reference, obligations, receipts, verifier); got.Status != RecoveryCompletable || ValidateBackupRecovery(got) != nil {
		t.Fatalf("complete = %#v", got)
	}
	failed := append([]CustodianReceipt(nil), receipts...)
	failed[0].Outcome = BackupFailed
	if got := ClassifyBackupRecovery(ctx, reference, obligations, failed, verifier); got.Status != RecoveryIncident || got.Reason != RecoveryReceiptFailed {
		t.Fatalf("failure = %#v", got)
	}
	late := append([]CustodianReceipt(nil), receipts...)
	late[1].EvidenceTime = "2026-08-06T00:00:00.000Z"
	if got := ClassifyBackupRecovery(ctx, reference, obligations, late, verifier); got.Status != RecoveryIncident || got.Reason != RecoveryDeadlineMissed {
		t.Fatalf("late = %#v", got)
	}
	if got := ClassifyBackupRecovery(ctx, reference, obligations, receipts, nil); got.Status != RecoveryCorrupt {
		t.Fatalf("unverified = %#v", got)
	}
}

func TestLaterSuccessCannotOverwriteFailure(t *testing.T) {
	obligations, receipts := backupFixture(t)
	failure := receipts[0]
	failure.Outcome = BackupFailed
	later := receipts[0]
	later.ReceiptID = "0198cf64-cc00-7000-8000-000000000099"
	later.EvidenceTime = "2026-08-04T01:00:00.000Z"
	got := ClassifyBackupRecovery(context.Background(), OperationReference{obligations[0].OperationID, obligations[0].IntentDigest}, obligations, append([]CustodianReceipt{failure, later}, receipts[1:]...), acceptingCustodianVerifier{})
	if got.Status != RecoveryIncident || got.Reason != RecoveryContradictoryEvidence {
		t.Fatalf("later success = %#v", got)
	}
}

func TestCompletionIsExplicitCrossBoundAndExactRetryOnly(t *testing.T) {
	obligations, receipts := backupFixture(t)
	evidence := completionFixture(t, receipts)
	if err := ValidateCompletionAgainst(context.Background(), evidence, obligations, receipts, acceptingCustodianVerifier{}); err != nil {
		t.Fatal(err)
	}
	changed := CloneCompletionEvidence(evidence)
	changed.SecurityAuditCheckpoint = "audit:checkpoint:replacement"
	if err := ValidateCompletionRetry(evidence, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement = %v", err)
	}
	reversed := CloneCompletionEvidence(evidence)
	reversed.Receipts[0], reversed.Receipts[1] = reversed.Receipts[1], reversed.Receipts[0]
	if err := ValidateCompletionEvidence(reversed); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("reversed = %v", err)
	}
}

func backupFixture(t *testing.T) ([]BackupObligation, []CustodianReceipt) {
	t.Helper()
	domains := []BackupDomain{EventBackupDomain, IdentityBackupDomain, AuditBackupDomain}
	obligations := make([]BackupObligation, 3)
	receipts := make([]CustodianReceipt, 3)
	for i, domain := range domains {
		binding := "sha-256:" + strings.Repeat(string(rune('c'+i)), 64)
		obligations[i] = BackupObligation{BackupObligationProfile, "0198cf64-cc00-7000-8000-000000000001", "sha-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", domain, "2026-08-05T00:00:00.000Z", BackupGeneration, binding}
		_, od, err := CanonicalBackupObligation(obligations[i])
		if err != nil {
			t.Fatal(err)
		}
		receipts[i] = CustodianReceipt{CustodianReceiptProfile, fmt.Sprintf("0198cf64-cc00-7000-8000-00000000000%d", i+2), od, obligations[i].OperationID, obligations[i].IntentDigest, obligations[i].PolicyDigest, domain, binding, "2026-08-04T00:00:00.000Z", GenerationRetired, BackupSucceeded, "custodian:" + string(domain), "backup-key-1", "ed25519", base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
	}
	return obligations, receipts
}

func completionFixture(t *testing.T, receipts []CustodianReceipt) CompletionEvidence {
	t.Helper()
	refs := make([]ReceiptEvidence, 3)
	for i, receipt := range receipts {
		_, digest, _, err := CanonicalCustodianReceipt(receipt)
		if err != nil {
			t.Fatal(err)
		}
		refs[i] = ReceiptEvidence{receipt.Domain, receipt.ReceiptID, digest}
	}
	return CompletionEvidence{CompletionEvidenceProfile, receipts[0].OperationID, receipts[0].IntentDigest, receipts[0].PolicyDigest, refs, "audit:receipt:42", "audit:checkpoint:9", "2026-08-04T01:00:00.000Z"}
}
