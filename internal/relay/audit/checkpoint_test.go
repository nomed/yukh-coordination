package audit_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
)

func TestCheckpointCanonicalSigningAndLifecycle(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytesOf(1, ed25519.SeedSize))
	authority := ed25519.NewKeyFromSeed(bytesOf(2, ed25519.SeedSize))
	issued := time.Date(2026, 8, 3, 9, 0, 0, 123_000_000, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "audit-checkpoint-7", Algorithm: audit.CheckpointAlgorithm,
		PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: issued.Add(-time.Hour), IssuedAt: issued.Add(-time.Hour)}
	statementCanonical, err := audit.CanonicalVerificationKeyStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	statementPreimage, err := audit.KeyStatementPreimage(statementCanonical)
	if err != nil {
		t.Fatal(err)
	}
	statementSignature := ed25519.Sign(authority, statementPreimage)
	parsed, err := audit.VerifyKeyStatement(authority.Public().(ed25519.PublicKey), statementCanonical, statementSignature)
	if err != nil || parsed.KeyID != statement.KeyID || !stringEqual(parsed.PublicKey, statement.PublicKey) {
		t.Fatalf("key statement = %#v, %v", parsed, err)
	}

	checkpoint := audit.Checkpoint{LedgerID: "0198f56b-0c00-7000-8000-000000000003", TreeSize: 7,
		RootHash: sha256.Sum256([]byte("root")), ChainHead: sha256.Sum256([]byte("head")), IssuedAt: issued,
		Algorithm: audit.CheckpointAlgorithm, KeyID: statement.KeyID}
	canonical, err := audit.CanonicalCheckpoint(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := audit.CheckpointPreimage(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, preimage)
	reference, err := audit.CheckpointReference(canonical, signature)
	if err != nil {
		t.Fatal(err)
	}
	signed := audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: canonical, Signature: signature, Reference: reference}
	trust, err := audit.VerifySignedCheckpoint(signed, statement)
	if err != nil || trust != audit.CheckpointTrusted {
		t.Fatalf("trust = %q, %v", trust, err)
	}

	compromised := issued.Add(-time.Minute)
	statement.Version = 2
	statement.CompromisedFrom = &compromised
	statement.IssuedAt = issued.Add(time.Minute)
	trust, err = audit.VerifySignedCheckpoint(signed, statement)
	if err != nil || trust != audit.CheckpointIndeterminate {
		t.Fatalf("compromised trust = %q, %v", trust, err)
	}

	tampered := signed
	tampered.Signature = append([]byte(nil), signature...)
	tampered.Signature[0] ^= 1
	if _, err := audit.VerifySignedCheckpoint(tampered, statement); err == nil {
		t.Fatal("tampered signature verified")
	}

	exported, err := audit.CanonicalCheckpointExport(signed, audit.SignedVerificationKeyStatement{Statement: parsed, Canonical: statementCanonical, Signature: statementSignature})
	if err != nil || len(exported) == 0 {
		t.Fatalf("export = %q, %v", exported, err)
	}
	ack := audit.WitnessAcknowledgement{WitnessID: "witness-1", CheckpointReference: reference, Canonical: witnessBytes(reference)}
	if err := audit.ValidateWitnessAcknowledgement(ack); err != nil {
		t.Fatal(err)
	}
	ack.Canonical = []byte(`{ "profile": "not-canonical" }`)
	if err := audit.ValidateWitnessAcknowledgement(ack); err == nil {
		t.Fatal("non-canonical acknowledgement accepted")
	}
}

func TestCheckpointRejectsMalformedAndSubstitutedMaterial(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytesOf(3, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "key-1", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: now, IssuedAt: now}
	canonical, err := audit.CanonicalVerificationKeyStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	badAuthority := ed25519.NewKeyFromSeed(bytesOf(4, ed25519.SeedSize))
	preimage, _ := audit.KeyStatementPreimage(canonical)
	if _, err := audit.VerifyKeyStatement(badAuthority.Public().(ed25519.PublicKey), canonical, ed25519.Sign(key, preimage)); err == nil {
		t.Fatal("substituted authority accepted")
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	decoded[0] ^= 1
	statement.PublicKey = decoded
	if _, err := audit.CanonicalVerificationKeyStatement(statement); err != nil {
		t.Fatalf("valid alternate public key rejected: %v", err)
	}
}

func TestCheckpointConsumesIndependentConformanceVector(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance")
	canonical, err := os.ReadFile(filepath.Join(root, "canonical", "audit-checkpoint.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := audit.ParseCanonicalCheckpoint(canonical)
	if err != nil {
		t.Fatal(err)
	}
	keyCanonical, err := os.ReadFile(filepath.Join(root, "canonical", "audit-verification-key.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	statement, err := audit.ParseCanonicalVerificationKeyStatement(keyCanonical)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SignatureHex string `json:"signature_hex"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "signatures", "audit-checkpoint-ed25519-rfc8032.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(vector.SignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := audit.CheckpointReference(canonical, signature)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := audit.VerifySignedCheckpoint(audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: canonical, Signature: signature, Reference: reference}, statement)
	if err != nil || trust != audit.CheckpointTrusted {
		t.Fatalf("vector trust = %q, %v", trust, err)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}
func stringEqual(left, right []byte) bool { return string(left) == string(right) }
func witnessBytes(reference string) []byte {
	return []byte(`{"algorithm":"Ed25519","checkpoint_reference":"` + reference + `","key_id":"witness-key-1","observed_at":"2026-08-03T09:01:00.000Z","profile":"yukh-security-audit-witness/v1","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `","witness_id":"witness-1"}`)
}
