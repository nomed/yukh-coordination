package audit_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func TestRecoveryManifestCanonicalSignatureAndBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytesOf(21, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 13, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "recovery-key-1", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: now.Add(-time.Hour), IssuedAt: now.Add(-time.Hour)}
	root := sha256.Sum256([]byte("root"))
	head := sha256.Sum256([]byte("head"))
	checkpoint := audit.Checkpoint{LedgerID: "0198f56b-0c00-7000-8000-000000000003", TreeSize: 7, RootHash: root, ChainHead: head, IssuedAt: now.Add(-time.Minute), Algorithm: audit.CheckpointAlgorithm, KeyID: statement.KeyID}
	checkpointCanonical, _ := audit.CanonicalCheckpoint(checkpoint)
	checkpointPreimage, _ := audit.CheckpointPreimage(checkpointCanonical)
	checkpointSignature := ed25519.Sign(key, checkpointPreimage)
	checkpointReference, _ := audit.CheckpointReference(checkpointCanonical, checkpointSignature)
	signedCheckpoint := audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: checkpointCanonical, Signature: checkpointSignature, Reference: checkpointReference}
	manifest := audit.RecoveryManifest{ManifestID: "0198f56b-0c00-7000-8000-000000000010",
		IdentityBackup:      audit.BackupEvidence{BackupID: "0198f56b-0c00-7000-8000-000000000011", DatabaseID: "0198f56b-0c00-7000-8000-000000000012", Digest: sha256.Sum256([]byte("identity")), CapturedAt: now.Add(-30 * time.Second)},
		AuditBackup:         audit.BackupEvidence{BackupID: "0198f56b-0c00-7000-8000-000000000013", DatabaseID: checkpoint.LedgerID, Digest: sha256.Sum256([]byte("audit")), CapturedAt: now.Add(-20 * time.Second)},
		AuditBackupTreeHead: audit.TreeHead{Size: 7, Root: root}, CheckpointReference: checkpointReference, CheckpointTreeHead: audit.TreeHead{Size: 7, Root: root}, CheckpointConsistency: audit.ConsistencyProof{FirstSize: 7, SecondSize: 7},
		IdentityEpochFloors: []identity.EpochFloor{{TenantID: "tenant-a", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Epoch: 9}}, IdentityWallHighWater: now.Add(-time.Minute), CreatedAt: now, Algorithm: audit.CheckpointAlgorithm, KeyID: statement.KeyID}
	canonical, err := audit.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	preimage, _ := audit.RecoveryManifestPreimage(canonical)
	signature := ed25519.Sign(key, preimage)
	reference, _ := audit.RecoveryManifestReference(canonical, signature)
	signed := audit.SignedRecoveryManifest{Manifest: manifest, Canonical: canonical, Signature: signature, Reference: reference}
	if err := audit.VerifySignedRecoveryManifest(signed, statement, signedCheckpoint, statement); err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Signature = append([]byte(nil), signature...)
	tampered.Signature[0] ^= 1
	if err := audit.VerifySignedRecoveryManifest(tampered, statement, signedCheckpoint, statement); err == nil {
		t.Fatal("tampered recovery signature verified")
	}
	reversed := manifest
	reversed.IdentityEpochFloors = append(reversed.IdentityEpochFloors, identity.EpochFloor{TenantID: "tenant-0", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Epoch: 1})
	if _, err := audit.CanonicalRecoveryManifest(reversed); err == nil {
		t.Fatal("unsorted floors accepted")
	}
}

func TestDigestBackupFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "backup.db")
	if err := os.WriteFile(target, []byte("backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := audit.DigestBackupFile(target)
	if err != nil || first != sha256.Sum256([]byte("backup")) {
		t.Fatalf("digest = %x, %v", first, err)
	}
	link := filepath.Join(directory, "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.DigestBackupFile(link); err == nil {
		t.Fatal("symlink backup accepted")
	}
}

func TestRecoveryConsumesIndependentConformanceVector(t *testing.T) {
	root := filepath.Join("..", "..", "..", "conformance")
	keyCanonical, err := os.ReadFile(filepath.Join(root, "canonical", "audit-verification-key.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	statement, err := audit.ParseCanonicalVerificationKeyStatement(keyCanonical)
	if err != nil {
		t.Fatal(err)
	}
	checkpointCanonical, err := os.ReadFile(filepath.Join(root, "canonical", "audit-checkpoint.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := audit.ParseCanonicalCheckpoint(checkpointCanonical)
	if err != nil {
		t.Fatal(err)
	}
	checkpointSignature := readSignature(t, filepath.Join(root, "signatures", "audit-checkpoint-ed25519-rfc8032.json"))
	checkpointReference, err := audit.CheckpointReference(checkpointCanonical, checkpointSignature)
	if err != nil {
		t.Fatal(err)
	}
	signedCheckpoint := audit.SignedCheckpoint{Checkpoint: checkpoint, Canonical: checkpointCanonical, Signature: checkpointSignature, Reference: checkpointReference}
	manifestCanonical, err := os.ReadFile(filepath.Join(root, "canonical", "audit-recovery-manifest.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := audit.ParseCanonicalRecoveryManifest(manifestCanonical)
	if err != nil {
		t.Fatal(err)
	}
	manifestSignature := readSignature(t, filepath.Join(root, "signatures", "audit-recovery-manifest-ed25519-rfc8032.json"))
	manifestReference, err := audit.RecoveryManifestReference(manifestCanonical, manifestSignature)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest := audit.SignedRecoveryManifest{Manifest: manifest, Canonical: manifestCanonical, Signature: manifestSignature, Reference: manifestReference}
	if err := audit.VerifySignedRecoveryManifest(signedManifest, statement, signedCheckpoint, statement); err != nil {
		t.Fatal(err)
	}
}

func readSignature(t *testing.T, path string) []byte {
	t.Helper()
	var vector struct {
		SignatureHex string `json:"signature_hex"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid signature vector")
	}
	signature, err := hex.DecodeString(vector.SignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}
