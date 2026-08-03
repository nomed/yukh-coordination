package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func TestRecoveryManifestRestoreFenceAndOperationalReadiness(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	livePath := filepath.Join(directory, "live.db")
	backupPath := filepath.Join(directory, "audit-backup.db")
	restoredPath := filepath.Join(directory, "restored.db")
	ledger := openLedger(t, livePath)
	for i := 1; i <= 3; i++ {
		if _, err := ledger.Append(ctx, testRecord(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	authority := ed25519.NewKeyFromSeed(repeatedByte(22, ed25519.SeedSize))
	key := ed25519.NewKeyFromSeed(repeatedByte(23, ed25519.SeedSize))
	captured := time.Date(2026, 8, 3, 13, 30, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "recovery-key-2", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: captured.Add(-time.Hour), IssuedAt: captured.Add(-time.Hour)}
	installStatement(t, ledger, authority, statement)
	checkpointSigner := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key}
	checkpoint, err := ledger.CreateCheckpoint(ctx, captured, authority.Public().(ed25519.PublicKey), checkpointSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	copyFile(t, livePath, backupPath)
	backupDigest, err := audit.DigestBackupFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err = Open(livePath)
	if err != nil {
		t.Fatal(err)
	}
	identityID := mustV7(t)
	manifestID := mustV7(t)
	identityBackupID := mustV7(t)
	auditBackupID := mustV7(t)
	input := audit.RecoveryManifestInput{ManifestID: manifestID, IdentityBackup: audit.BackupEvidence{BackupID: identityBackupID, DatabaseID: identityID, Digest: sha256.Sum256([]byte("identity-backup")), CapturedAt: captured},
		AuditBackup: audit.BackupEvidence{BackupID: auditBackupID, DatabaseID: checkpoint.Checkpoint.LedgerID, Digest: backupDigest, CapturedAt: captured}, AuditBackupTreeSize: checkpoint.Checkpoint.TreeSize, CheckpointReference: checkpoint.Reference,
		IdentityEpochFloors: []identity.EpochFloor{{TenantID: "tenant-a", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Epoch: 12}}, IdentityWallHighWater: captured, CreatedAt: captured.Add(time.Minute)}
	recoverySigner := &testRecoverySigner{selection: audit.RecoverySigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key}
	manifest, err := ledger.CreateRecoveryManifest(ctx, input, authority.Public().(ed25519.PublicKey), recoverySigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	copyFile(t, backupPath, restoredPath)
	wrong := backupDigest
	wrong[0] ^= 1
	if opened, err := OpenRestored(restoredPath, wrong); err == nil {
		_ = opened.Close()
		t.Fatal("wrong backup digest admitted")
	}
	restored, err := OpenRestored(restoredPath, backupDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	if _, err := restored.Append(ctx, testRecord(t, 4)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("fenced append = %v", err)
	}
	if err := restored.InstallVerificationKey(ctx, audit.SignedVerificationKeyStatement{}, authority.Public().(ed25519.PublicKey)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("fenced key install = %v", err)
	}
	policy := audit.ReadinessPolicy{MaximumCheckpointAge: time.Hour, ClockRollbackTolerance: time.Minute, MaximumEntries: 10_000, MaximumDatabaseBytes: 64 << 20}
	if err := restored.OperationalReady(ctx, captured.Add(2*time.Minute), authority.Public().(ed25519.PublicKey), policy, checkpointSigner, testSignerProbe{}, nil); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("fenced readiness = %v", err)
	}
	plan, err := restored.ValidateRestore(ctx, manifest, authority.Public().(ed25519.PublicKey))
	if err != nil || plan.IdentityDatabaseID() != identityID || plan.IdentityWallHighWater() != captured || len(plan.EpochFloors()) != 1 {
		t.Fatalf("plan = %#v, %v", plan, err)
	}
	if err := restored.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err = Open(restoredPath)
	if err != nil {
		t.Fatalf("fenced restore did not verify on restart: %v", err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	if _, err := restored.ValidateRestore(ctx, manifest, authority.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("restore validation after restart = %v", err)
	}
	if err := restored.OperationalReady(ctx, captured.Add(2*time.Minute), authority.Public().(ed25519.PublicKey), policy, checkpointSigner, testSignerProbe{}, nil); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("restore fence bypassed after restart = %v", err)
	}
}

func TestRestoreRejectsManifestForDifferentBackup(t *testing.T) {
	// The pure manifest verifier covers signatures and bindings; this test locks
	// the database-local digest gate independently.
	path := filepath.Join(t.TempDir(), "audit.db")
	ledger := openLedger(t, path)
	if _, err := ledger.Append(context.Background(), testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	digest, err := audit.DigestBackupFile(path)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OpenRestored(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, err := restored.ValidateRestore(context.Background(), audit.SignedRecoveryManifest{}, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("empty manifest = %v", err)
	}
}

func TestOperationalStateRejectsArbitraryTransitions(t *testing.T) {
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	if _, err := ledger.db.Exec(`UPDATE audit_operational_state SET fence_state = 'restore_fenced', restore_backup_digest = randomblob(32), accepted_manifest_reference = 'audit-recovery:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE singleton = 1`); err == nil {
		t.Fatal("invalid operational transition accepted")
	}
	if _, err := ledger.db.Exec(`UPDATE audit_operational_state SET wall_high_water_ms = -1 WHERE singleton = 1`); err == nil {
		t.Fatal("clock high-water rollback accepted")
	}
	if _, err := ledger.db.Exec(`DELETE FROM audit_operational_state WHERE singleton = 1`); err == nil {
		t.Fatal("operational state deleted")
	}
}

func TestOperationalReadyReverifiesWitness(t *testing.T) {
	ctx := context.Background()
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	if _, err := ledger.Append(ctx, testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	authority := ed25519.NewKeyFromSeed(repeatedByte(24, ed25519.SeedSize))
	key := ed25519.NewKeyFromSeed(repeatedByte(25, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 14, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "readiness-key-1", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: now.Add(-time.Hour), IssuedAt: now.Add(-time.Hour)}
	installStatement(t, ledger, authority, statement)
	signer := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key}
	checkpoint, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.WitnessCheckpoint(ctx, checkpoint.Reference, authority.Public().(ed25519.PublicKey), &testWitness{reference: checkpoint.Reference}, testWitnessVerifier{}); err != nil {
		t.Fatal(err)
	}
	policy := audit.ReadinessPolicy{MaximumCheckpointAge: time.Hour, ClockRollbackTolerance: time.Minute, RequireWitness: true, MaximumEntries: 100, MaximumDatabaseBytes: 64 << 20}
	if err := ledger.OperationalReady(ctx, now, authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{}, testWitnessVerifier{}); err != nil {
		t.Fatalf("witnessed readiness = %v", err)
	}
	if err := ledger.OperationalReady(ctx, now, authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{}, rejectingWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("unverified witness = %v", err)
	}
	capacity := policy
	capacity.MaximumEntries = 1
	if err := ledger.OperationalReady(ctx, now, authority.Public().(ed25519.PublicKey), capacity, signer, testSignerProbe{}, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("capacity fence = %v", err)
	}
	if err := ledger.OperationalReady(ctx, now, authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{err: errors.New("signer unavailable")}, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("signer readiness = %v", err)
	}
	if err := ledger.OperationalReady(ctx, now.Add(2*time.Hour), authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{}, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("stale checkpoint = %v", err)
	}
	if err := ledger.OperationalReady(ctx, now.Add(-10*time.Minute), authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{}, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("clock rollback = %v", err)
	}
	if err := ledger.OperationalReady(ctx, now.Add(3*time.Hour), authority.Public().(ed25519.PublicKey), policy, signer, testSignerProbe{}, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("clock fence bypassed = %v", err)
	}
}

type testRecoverySigner struct {
	selection  audit.RecoverySigningSelection
	privateKey ed25519.PrivateKey
}

func (s *testRecoverySigner) SelectRecovery(context.Context) (audit.RecoverySigningSelection, error) {
	return s.selection, nil
}
func (s *testRecoverySigner) SignRecovery(_ context.Context, selection audit.RecoverySigningSelection, preimage []byte) ([]byte, error) {
	if selection != s.selection {
		return nil, audit.ErrUnavailable
	}
	return ed25519.Sign(s.privateKey, preimage), nil
}

type testSignerProbe struct{ err error }

func (p testSignerProbe) CheckSigner(context.Context, audit.CheckpointSigningSelection) error {
	return p.err
}

type rejectingWitnessVerifier struct{}

func (rejectingWitnessVerifier) VerifyWitness(context.Context, audit.WitnessAcknowledgement) error {
	return audit.ErrUnavailable
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustV7(t *testing.T) string {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}
