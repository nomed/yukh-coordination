package sqlite

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
)

func TestSignedCheckpointLifecycleExportAndWitness(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "audit.db")
	ledger := openLedger(t, databasePath)
	for i := 1; i <= 3; i++ {
		if _, err := ledger.Append(ctx, testRecord(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	authority := ed25519.NewKeyFromSeed(repeatedByte(9, ed25519.SeedSize))
	checkpointKey := ed25519.NewKeyFromSeed(repeatedByte(7, ed25519.SeedSize))
	active := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "checkpoint-key-1", Algorithm: audit.CheckpointAlgorithm,
		PublicKey: checkpointKey.Public().(ed25519.PublicKey), ActiveFrom: active, IssuedAt: active}
	installStatement(t, ledger, authority, statement)
	signer := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: checkpointKey}
	issued := active.Add(time.Hour)
	checkpointOperationID := mustV7(t)
	first, err := ledger.CreateCheckpoint(ctx, issued, authority.Public().(ed25519.PublicKey), signer, checkpointOperationID)
	if err != nil || first.Checkpoint.TreeSize != 5 || first.Checkpoint.PredecessorReference != "" {
		t.Fatalf("first checkpoint = %#v, %v", first, err)
	}
	if retry, err := ledger.CreateCheckpoint(ctx, issued, authority.Public().(ed25519.PublicKey), signer, checkpointOperationID); err != nil || retry.Reference != first.Reference {
		t.Fatalf("checkpoint retry = %#v, %v", retry, err)
	}
	latest, trust, err := ledger.LatestCheckpoint(ctx, authority.Public().(ed25519.PublicKey))
	if err != nil || trust != audit.CheckpointTrusted || latest.Reference != first.Reference {
		t.Fatalf("latest = %#v, %q, %v", latest, trust, err)
	}
	exported, err := ledger.ExportCheckpoint(ctx, first.Reference, authority.Public().(ed25519.PublicKey))
	if err != nil || !json.Valid(exported) {
		t.Fatalf("export = %q, %v", exported, err)
	}

	witness := &testWitness{reference: first.Reference}
	ack, err := ledger.WitnessCheckpoint(ctx, first.Reference, authority.Public().(ed25519.PublicKey), witness, testWitnessVerifier{})
	if err != nil || ack.WitnessID != "witness-1" {
		t.Fatalf("ack = %#v, %v", ack, err)
	}
	if _, err := ledger.WitnessCheckpoint(ctx, first.Reference, authority.Public().(ed25519.PublicKey), witness, testWitnessVerifier{}); err != nil {
		t.Fatalf("idempotent witness = %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = Open(databasePath)
	if err != nil {
		t.Fatalf("checkpoint ledger did not reopen: %v", err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	compromised := issued.Add(-time.Minute)
	statement.Version = 2
	statement.IssuedAt = issued.Add(time.Minute)
	statement.CompromisedFrom = &compromised
	installStatement(t, ledger, authority, statement)
	_, trust, err = ledger.LatestCheckpoint(ctx, authority.Public().(ed25519.PublicKey))
	if err != nil || trust != audit.CheckpointIndeterminate {
		t.Fatalf("compromised trust = %q, %v", trust, err)
	}
	if _, err := ledger.WitnessCheckpoint(ctx, first.Reference, authority.Public().(ed25519.PublicKey), witness, testWitnessVerifier{}); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("compromised checkpoint witnessed: %v", err)
	}

	if _, err := ledger.Append(ctx, testRecord(t, 4)); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.CreateCheckpoint(ctx, issued.Add(2*time.Minute), authority.Public().(ed25519.PublicKey), signer, mustV7(t)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("compromised key created checkpoint: %v", err)
	}
}

func TestCheckpointRejectsSignerSubstitutionAndHeadRace(t *testing.T) {
	ctx := context.Background()
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	if _, err := ledger.Append(ctx, testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	authority := ed25519.NewKeyFromSeed(repeatedByte(5, ed25519.SeedSize))
	key := ed25519.NewKeyFromSeed(repeatedByte(6, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "checkpoint-key-2", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: now, IssuedAt: now}
	installStatement(t, ledger, authority, statement)
	bad := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: ed25519.NewKeyFromSeed(repeatedByte(8, ed25519.SeedSize))}
	if _, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), bad, mustV7(t)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("substituted key = %v", err)
	}
	outage := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key, signErr: errors.New("signer unavailable")}
	if _, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), outage, mustV7(t)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("signer outage = %v", err)
	}
	racing := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key,
		onSign: func() { _, _ = ledger.Append(ctx, testRecord(t, 2)) }}
	if _, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), racing, mustV7(t)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("moving head = %v", err)
	}
}

func TestCheckpointRotationRetirementAndPredecessor(t *testing.T) {
	ctx := context.Background()
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	authority := ed25519.NewKeyFromSeed(repeatedByte(12, ed25519.SeedSize))
	firstKey := ed25519.NewKeyFromSeed(repeatedByte(13, ed25519.SeedSize))
	secondKey := ed25519.NewKeyFromSeed(repeatedByte(14, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	firstStatement := audit.VerificationKeyStatement{Version: 1, KeyID: "rotation-key-1", Algorithm: audit.CheckpointAlgorithm, PublicKey: firstKey.Public().(ed25519.PublicKey), ActiveFrom: now, IssuedAt: now}
	installStatement(t, ledger, authority, firstStatement)
	if _, err := ledger.Append(ctx, testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	first, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: firstStatement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: firstKey}, mustV7(t))
	if err != nil {
		t.Fatal(err)
	}
	secondStatement := audit.VerificationKeyStatement{Version: 1, KeyID: "rotation-key-2", Algorithm: audit.CheckpointAlgorithm, PublicKey: secondKey.Public().(ed25519.PublicKey), ActiveFrom: now.Add(time.Minute), IssuedAt: now.Add(time.Minute)}
	installStatement(t, ledger, authority, secondStatement)
	if _, err := ledger.Append(ctx, testRecord(t, 2)); err != nil {
		t.Fatal(err)
	}
	second, err := ledger.CreateCheckpoint(ctx, now.Add(time.Minute), authority.Public().(ed25519.PublicKey), &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: secondStatement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: secondKey}, mustV7(t))
	if err != nil || second.Checkpoint.PredecessorReference != first.Reference {
		t.Fatalf("rotated checkpoint = %#v, %v", second, err)
	}
	retired := now.Add(time.Minute)
	firstStatement.Version = 2
	firstStatement.IssuedAt = now.Add(2 * time.Minute)
	firstStatement.RetiredAt = &retired
	installStatement(t, ledger, authority, firstStatement)
	if _, err := ledger.ExportCheckpoint(ctx, first.Reference, authority.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("historical checkpoint invalidated by normal retirement: %v", err)
	}
	latest, trust, err := ledger.LatestCheckpoint(ctx, authority.Public().(ed25519.PublicKey))
	if err != nil || trust != audit.CheckpointTrusted || latest.Reference != second.Reference {
		t.Fatalf("latest after rotation = %#v, %q, %v", latest, trust, err)
	}
}

func TestOpenRejectsTamperedCheckpointEvidence(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "audit.db")
	ledger := openLedger(t, databasePath)
	if _, err := ledger.Append(ctx, testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	authority := ed25519.NewKeyFromSeed(repeatedByte(10, ed25519.SeedSize))
	key := ed25519.NewKeyFromSeed(repeatedByte(11, ed25519.SeedSize))
	now := time.Date(2026, 8, 3, 11, 0, 0, 0, time.UTC)
	statement := audit.VerificationKeyStatement{Version: 1, KeyID: "checkpoint-key-3", Algorithm: audit.CheckpointAlgorithm, PublicKey: key.Public().(ed25519.PublicKey), ActiveFrom: now, IssuedAt: now}
	keyOperationID := installStatement(t, ledger, authority, statement)
	// Installing the same signed evidence is an exact idempotent retry.
	installStatementWithOperation(t, ledger, authority, statement, keyOperationID)
	signer := &testCheckpointSigner{selection: audit.CheckpointSigningSelection{KeyID: statement.KeyID, Algorithm: audit.CheckpointAlgorithm}, privateKey: key}
	if _, err := ledger.CreateCheckpoint(ctx, now, authority.Public().(ed25519.PublicKey), signer, mustV7(t)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, databasePath)
	if _, err := db.Exec(`DROP TRIGGER audit_checkpoints_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE audit_checkpoints SET signature = randomblob(64)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if opened, err := Open(databasePath); err == nil {
		_ = opened.Close()
		t.Fatal("tampered checkpoint ledger opened")
	}
}

func installStatement(t *testing.T, ledger *Ledger, authority ed25519.PrivateKey, statement audit.VerificationKeyStatement) string {
	t.Helper()
	operationID := mustV7(t)
	installStatementWithOperation(t, ledger, authority, statement, operationID)
	return operationID
}

func installStatementWithOperation(t *testing.T, ledger *Ledger, authority ed25519.PrivateKey, statement audit.VerificationKeyStatement, operationID string) {
	t.Helper()
	canonical, err := audit.CanonicalVerificationKeyStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	preimage, err := audit.KeyStatementPreimage(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signed := audit.SignedVerificationKeyStatement{Statement: statement, Canonical: canonical, Signature: ed25519.Sign(authority, preimage)}
	if err := ledger.InstallVerificationKey(context.Background(), signed, authority.Public().(ed25519.PublicKey), operationID, statement.IssuedAt, "authority:key-lifecycle:1"); err != nil {
		t.Fatal(err)
	}
}

type testCheckpointSigner struct {
	selection  audit.CheckpointSigningSelection
	privateKey ed25519.PrivateKey
	onSign     func()
	selectErr  error
	signErr    error
}

func (s *testCheckpointSigner) Select(context.Context) (audit.CheckpointSigningSelection, error) {
	return s.selection, s.selectErr
}
func (s *testCheckpointSigner) Sign(_ context.Context, selection audit.CheckpointSigningSelection, preimage []byte) ([]byte, error) {
	if selection != s.selection {
		return nil, audit.ErrUnavailable
	}
	if s.signErr != nil {
		return nil, s.signErr
	}
	if s.onSign != nil {
		s.onSign()
	}
	return ed25519.Sign(s.privateKey, preimage), nil
}

type testWitness struct{ reference string }

func (w *testWitness) Witness(context.Context, []byte) (audit.WitnessAcknowledgement, error) {
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	canonical := []byte(`{"algorithm":"Ed25519","checkpoint_reference":"` + w.reference + `","key_id":"witness-key-1","observed_at":"2026-08-03T09:01:00.000Z","profile":"yukh-security-audit-witness/v1","signature":"` + signature + `","witness_id":"witness-1"}`)
	return audit.WitnessAcknowledgement{WitnessID: "witness-1", CheckpointReference: w.reference, Canonical: canonical}, nil
}

type testWitnessVerifier struct{}

func (testWitnessVerifier) VerifyWitness(context.Context, audit.WitnessAcknowledgement) error {
	return nil
}
func repeatedByte(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}
