package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const (
	fixtureOperationID = "0198f56b-0c00-7000-8000-000000000001"
	fixtureParticipant = "0198f56b-0c00-7000-8000-000000000002"
	fixtureLedgerID    = "0198f56b-0c00-7000-8000-000000000003"
)

func TestCanonicalRecordAndReceiptFixture(t *testing.T) {
	record := fixtureAuditRecord()
	fixtureRecord := readFixture(t, "audit-record.canonical.json")
	fixtureReceipt := readFixture(t, "audit-receipt.canonical.json")
	canonical, err := CanonicalRecord(record)
	if err != nil || !bytes.Equal(canonical, fixtureRecord) {
		t.Fatalf("canonical record = %q, %v", canonical, err)
	}
	if err := ValidateCanonicalRecord(canonical); err != nil {
		t.Fatal(err)
	}
	recordDigest := RecordDigest(canonical)
	if got := base64.RawURLEncoding.EncodeToString(recordDigest[:]); got != "MiT_YZIr0Uo-FpgWG2CtlylPzGhrc8lhm3E9tYQ-sgo" {
		t.Fatalf("record digest = %s", got)
	}
	genesis, err := GenesisDigest(fixtureLedgerID)
	if err != nil || base64.RawURLEncoding.EncodeToString(genesis[:]) != "DkWypfXwVVtmwS0EcyWtE-k3Yrlt0jRZgLE-q5KwFus" {
		t.Fatalf("genesis = %x, %v", genesis, err)
	}
	chain, err := ChainDigest(1, genesis, recordDigest)
	if err != nil || base64.RawURLEncoding.EncodeToString(chain[:]) != "5EFkrBY6WcVnhjTg8AItaK3GkkGZzGBWf3xE_IeD7nM" {
		t.Fatalf("chain = %x, %v", chain, err)
	}
	receipt, err := NewReceipt(fixtureLedgerID, 1, record.OperationID, recordDigest, genesis, chain)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalReceipt(receipt)
	if err != nil || !bytes.Equal(encoded, fixtureReceipt) {
		t.Fatalf("canonical receipt = %q, %v", encoded, err)
	}
	if got := receipt.Reference(); got != "audit:"+fixtureLedgerID+":1:5EFkrBY6WcVnhjTg8AItaK3GkkGZzGBWf3xE_IeD7nM" {
		t.Fatalf("reference = %q", got)
	}
}

func TestValidateCanonicalRecordRejectsStoredShapeDamage(t *testing.T) {
	fixtureRecord := string(readFixture(t, "audit-record.canonical.json"))
	for _, damaged := range []string{
		`{"profile":"yukh-security-audit/v1"}`,
		strings.Replace(fixtureRecord, `"profile":`, `"unknown":true,"profile":`, 1),
		strings.Replace(fixtureRecord, `"outcome":"allow"`, `"outcome":"deny"`, 1),
		strings.Replace(fixtureRecord, `{"decision_time"`, `{ "decision_time"`, 1),
		strings.Replace(fixtureRecord, `"reason":"allowed"`, `"reason":"allowed","reason":"allowed"`, 1),
	} {
		if err := ValidateCanonicalRecord([]byte(damaged)); err == nil {
			t.Fatalf("damaged stored record accepted: %s", damaged)
		}
	}
}

func TestCanonicalRestoreFenceRecordFixture(t *testing.T) {
	record := identity.AuditRecord{ProfileVersion: 1, OperationID: "0198f56b-0c00-7000-8000-000000000014", Operation: identity.AuditRestoreFence, Outcome: identity.AuditAllow, Reason: identity.AuditReasonRestoreVerified, DecisionTime: time.Date(2026, 8, 3, 9, 2, 0, 0, time.UTC), CheckpointReference: "audit-checkpoint:ciLVHmYlmHAylKq0SHZ1cmWijlvuMBCaXGRuOrV3VYE", RecoveryReference: "audit-recovery:mNlOuRruflqKK7uFDCLYVkiC_xXm6cw3Ev-Hn7pd6ps"}
	canonical, err := CanonicalRecord(record)
	if err != nil || !bytes.Equal(canonical, readFixture(t, "audit-record-restore-fence.canonical.json")) {
		t.Fatalf("canonical restore fence = %q, %v", canonical, err)
	}
	if err := ValidateCanonicalRecord(canonical); err != nil {
		t.Fatal(err)
	}
	record.CheckpointReference = "audit-checkpoint:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	record.RecoveryReference = ""
	if _, err := CanonicalRecord(record); err == nil {
		t.Fatal("restore record without manifest binding accepted")
	}
}

func TestAdministrativeAuditVocabularyIsClosed(t *testing.T) {
	jwks := sha256.Sum256([]byte("jwks"))
	base := identity.AuditRecord{ProfileVersion: 1, OperationID: fixtureOperationID, Outcome: identity.AuditAllow, DecisionTime: time.Date(2026, 8, 3, 9, 3, 0, 0, time.UTC)}
	records := []identity.AuditRecord{
		func() identity.AuditRecord {
			v := base
			v.Operation = identity.AuditRevocation
			v.Reason = identity.AuditReasonRevoked
			v.TenantID = "tenant-a"
			v.ParticipantInstanceID = fixtureParticipant
			v.SessionEpoch = 7
			v.AuthorityReference = "authority:revocation:1"
			return v
		}(),
		func() identity.AuditRecord {
			v := base
			v.Operation = identity.AuditJWKSRefresh
			v.Reason = identity.AuditReasonRefreshed
			v.AuthorityReference = "issuer:key-set:1"
			v.JWKSSetDigest = jwks
			v.HasJWKSSetDigest = true
			return v
		}(),
		func() identity.AuditRecord {
			v := base
			v.Operation = identity.AuditCheckpoint
			v.Reason = identity.AuditReasonCheckpointCommitted
			v.SigningKeyReference = "signing-key:key-1:1"
			return v
		}(),
		func() identity.AuditRecord {
			v := base
			v.Operation = identity.AuditKeyLifecycle
			v.Reason = identity.AuditReasonKeyLifecycleCommitted
			v.AuthorityReference = "authority:key-statement:1"
			v.SigningKeyReference = "signing-key:key-1:1"
			return v
		}(),
	}
	for _, record := range records {
		canonical, err := CanonicalRecord(record)
		if err != nil || ValidateCanonicalRecord(canonical) != nil {
			t.Fatalf("%s record = %q, %v", record.Operation, canonical, err)
		}
		damaged := record
		damaged.RecoveryReference = "audit-recovery:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		if _, err := CanonicalRecord(damaged); err == nil {
			t.Fatalf("%s accepted an inapplicable field", record.Operation)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "canonical", name))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCanonicalRecordRejectsOpenOrMalformedShapes(t *testing.T) {
	valid := fixtureAuditRecord()
	tests := []identity.AuditRecord{
		{},
		func() identity.AuditRecord { v := valid; v.ProfileVersion = 2; return v }(),
		func() identity.AuditRecord { v := valid; v.OperationID = "not-a-uuid"; return v }(),
		func() identity.AuditRecord { v := valid; v.Operation = "future"; return v }(),
		func() identity.AuditRecord { v := valid; v.Reason = identity.AuditReasonProofReplay; return v }(),
		func() identity.AuditRecord {
			v := valid
			v.DecisionTime = v.DecisionTime.Add(time.Microsecond)
			return v
		}(),
		func() identity.AuditRecord { v := valid; v.TenantID = "Tenant A"; return v }(),
		func() identity.AuditRecord { v := valid; v.HasDPoPThumbprint = false; return v }(),
	}
	for i, record := range tests {
		if _, err := CanonicalRecord(record); err == nil {
			t.Fatalf("invalid record %d accepted", i)
		}
	}
}

func fixtureAuditRecord() identity.AuditRecord {
	principal := sha256.Sum256([]byte("principal"))
	thumbprint := sha256.Sum256([]byte("thumbprint"))
	return identity.AuditRecord{
		ProfileVersion: 1, OperationID: fixtureOperationID, Operation: identity.AuditBootstrap,
		Outcome: identity.AuditAllow, Reason: identity.AuditReasonAllowed,
		DecisionTime: time.Date(2026, 8, 3, 8, 0, 0, 123_000_000, time.UTC),
		TenantID:     "tenant-a", PrincipalID: base64.RawURLEncoding.EncodeToString(principal[:]),
		ParticipantInstanceID: fixtureParticipant, SessionEpoch: 7,
		DPoPThumbprint: thumbprint, HasDPoPThumbprint: true,
	}
}
