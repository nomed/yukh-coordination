package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

func TestBootstrapAuthenticationReplayAndRevocationLifecycle(t *testing.T) {
	registry, clock := openTestRegistry(t)
	request := bootstrapRequest(t, clock.read(), 1)
	pending, err := registry.ReserveBootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if pending.SessionEpoch != 1 {
		t.Fatalf("first epoch = %d, want 1", pending.SessionEpoch)
	}

	replay := bootstrapRequest(t, clock.read(), 2)
	replay.ProofJTI = request.ProofJTI
	replay.Session.DPoPThumbprint = request.Session.DPoPThumbprint
	if _, err := registry.ReserveBootstrap(context.Background(), replay); !errors.Is(err, identity.ErrProofReplay) {
		t.Fatalf("bootstrap replay accepted: %v", err)
	}

	active, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:bootstrap:1")
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:bootstrap:1"); err != nil || retry != active {
		t.Fatalf("activation retry was not idempotent: %#v, %v", retry, err)
	}
	if _, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:other"); !errors.Is(err, identity.ErrSessionConflict) {
		t.Fatalf("conflicting activation accepted: %v", err)
	}

	auth := identity.AuthenticationReservation{
		TokenDigest: pending.TokenDigest, DPoPThumbprint: pending.DPoPThumbprint,
		ProofJTI: "authproofABCDEFGH", ProofIAT: clock.read(),
	}
	got, err := registry.Authenticate(context.Background(), auth)
	if err != nil || got.ParticipantInstanceID != pending.ParticipantInstanceID || got.SessionEpoch != 1 {
		t.Fatalf("authentication = %#v, %v", got, err)
	}
	if _, err := registry.Authenticate(context.Background(), auth); !errors.Is(err, identity.ErrProofReplay) {
		t.Fatalf("authentication replay accepted: %v", err)
	}
	wrong := auth
	wrong.DPoPThumbprint = digest("wrong-thumbprint")
	wrong.ProofJTI = "authproofIJKLMNOP"
	if _, err := registry.Authenticate(context.Background(), wrong); !errors.Is(err, identity.ErrSessionNotFound) {
		t.Fatalf("wrong binding disclosed session: %v", err)
	}

	key := identity.SessionKey{TenantID: active.TenantID, ParticipantInstanceID: active.ParticipantInstanceID, SessionEpoch: active.SessionEpoch}
	inactive, err := registry.SubscribeInactive(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	revocationID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	revocation := identity.Revocation{OperationID: revocationID.String(), Key: key, Reason: "operator-request", AuthorityReceipt: "audit:revoke:1"}
	if err := registry.Revoke(context.Background(), revocation); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(context.Background(), revocation); err != nil {
		t.Fatalf("revocation retry = %v", err)
	}
	changedID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	changed := revocation
	changed.OperationID = changedID.String()
	if err := registry.Revoke(context.Background(), changed); !errors.Is(err, identity.ErrSessionConflict) {
		t.Fatalf("revocation operation replacement = %v", err)
	}
	select {
	case <-inactive:
	default:
		t.Fatal("revocation committed without closing inactive signal")
	}
	if ok, err := registry.IsActive(context.Background(), key); err != nil || ok {
		t.Fatalf("revoked session active = %v, %v", ok, err)
	}
	if _, err := registry.Authenticate(context.Background(), identity.AuthenticationReservation{TokenDigest: pending.TokenDigest, DPoPThumbprint: pending.DPoPThumbprint, ProofJTI: "authproofQRSTUVW", ProofIAT: clock.read()}); !errors.Is(err, identity.ErrSessionNotFound) {
		t.Fatalf("revoked token admitted: %v", err)
	}
	next, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 3))
	if err != nil {
		t.Fatal(err)
	}
	if next.SessionEpoch != 2 {
		t.Fatalf("rolled-back replay consumed epoch: %d", next.SessionEpoch)
	}
}

func TestExpirySchedulerClosesInactiveSignal(t *testing.T) {
	registry, clock := openTestRegistry(t)
	request := bootstrapRequest(t, clock.read(), 1)
	request.Session.ExpiresAt = clock.read().Add(time.Second)
	pending, err := registry.ReserveBootstrap(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	active, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:bootstrap:1")
	if err != nil {
		t.Fatal(err)
	}
	key := identity.SessionKey{TenantID: active.TenantID, ParticipantInstanceID: active.ParticipantInstanceID, SessionEpoch: active.SessionEpoch}
	inactive, err := registry.SubscribeInactive(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(clock.read().Add(2 * time.Second))
	select {
	case <-inactive:
	case <-time.After(2 * time.Second):
		t.Fatal("expiry scheduler did not close inactive signal")
	}
	if ok, err := registry.IsActive(context.Background(), key); err != nil || ok {
		t.Fatalf("expired session active = %v, %v", ok, err)
	}
}

func TestIdleExpirySchedulerDoesNotAdvanceDurableClock(t *testing.T) {
	registry, clock := openTestRegistry(t)
	before, err := registry.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	clock.set(clock.read().Add(10 * time.Second))
	time.Sleep(1100 * time.Millisecond)
	after, err := registry.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !after.WallHighWater.Equal(before.WallHighWater) {
		t.Fatalf("idle scheduler wrote high-water: before=%s after=%s", before.WallHighWater, after.WallHighWater)
	}
}

func TestConcurrentProofReservationCommitsOnce(t *testing.T) {
	registry, clock := openTestRegistry(t)
	pending, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:bootstrap:1"); err != nil {
		t.Fatal(err)
	}
	request := identity.AuthenticationReservation{TokenDigest: pending.TokenDigest, DPoPThumbprint: pending.DPoPThumbprint, ProofJTI: "concurrentProof1", ProofIAT: clock.read()}
	const workers = 16
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := registry.Authenticate(context.Background(), request)
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(errorsSeen)
	var admitted, replayed int
	for err := range errorsSeen {
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, identity.ErrProofReplay):
			replayed++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if admitted != 1 || replayed != workers-1 {
		t.Fatalf("admitted=%d replayed=%d", admitted, replayed)
	}
}

func TestRestartAbandonsPendingAndConsumesEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	clock := &testClock{now: time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)}
	registry, err := Open(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	first, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = Open(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	if _, err := registry.ActivateBootstrap(context.Background(), first.BootstrapOperationID, "audit:late"); !errors.Is(err, identity.ErrSessionConflict) {
		t.Fatalf("old pending session activated: %v", err)
	}
	second, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 2))
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionEpoch != 2 {
		t.Fatalf("abandoned epoch reused: %d", second.SessionEpoch)
	}
}

func TestClockRollbackPersistsFenceAndRequiresRecovery(t *testing.T) {
	registry, clock := openTestRegistry(t)
	pending, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 1))
	if err != nil {
		t.Fatal(err)
	}
	active, err := registry.ActivateBootstrap(context.Background(), pending.BootstrapOperationID, "audit:bootstrap:1")
	if err != nil {
		t.Fatal(err)
	}
	key := identity.SessionKey{TenantID: active.TenantID, ParticipantInstanceID: active.ParticipantInstanceID, SessionEpoch: active.SessionEpoch}
	high := clock.read()
	clock.set(high.Add(-clockTolerance - time.Millisecond))
	if _, err := registry.IsActive(context.Background(), key); !errors.Is(err, identity.ErrClockRollback) {
		t.Fatalf("rollback not detected: %v", err)
	}
	status, err := registry.Status(context.Background())
	if err != nil || status.FenceState != "clock_fenced" {
		t.Fatalf("clock fence not durable: %#v, %v", status, err)
	}
	clock.set(high)
	if _, err := registry.IsActive(context.Background(), key); !errors.Is(err, identity.ErrRegistryFenced) {
		t.Fatalf("clock fence bypassed: %v", err)
	}
	if err := registry.RecoverClock(context.Background(), high, "audit:clock-recovery:1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := registry.IsActive(context.Background(), key); err != nil || !ok {
		t.Fatalf("recovered session active = %v, %v", ok, err)
	}
}

func TestRestoreFenceRequiresCompleteMonotonicFloors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	clock := &testClock{now: time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)}
	registry, err := Open(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	first, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 1))
	if err != nil {
		t.Fatal(err)
	}
	status, err := registry.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = OpenRestored(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	if _, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 2)); !errors.Is(err, identity.ErrRegistryFenced) {
		t.Fatalf("restored database admitted before checkpoint: %v", err)
	}
	manifestReference := "audit-recovery:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := registry.StageRestoreFloors(context.Background(), status.DatabaseID, manifestReference, status.WallHighWater, nil); !errors.Is(err, identity.ErrRegistryInvalid) {
		t.Fatalf("missing principal floor accepted: %v", err)
	}
	floors := []identity.EpochFloor{{TenantID: first.TenantID, PrincipalID: first.PrincipalID, Epoch: first.SessionEpoch + 9}}
	if err := registry.StageRestoreFloors(context.Background(), status.DatabaseID, manifestReference, status.WallHighWater, floors); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 2)); !errors.Is(err, identity.ErrRegistryFenced) {
		t.Fatalf("staged floors admitted identity: %v", err)
	}
	if err := registry.CompleteRestore(context.Background(), status.DatabaseID, manifestReference, "audit:restore:1"); err != nil {
		t.Fatal(err)
	}
	if err := registry.CompleteRestore(context.Background(), status.DatabaseID, manifestReference, "audit:restore:1"); err != nil {
		t.Fatalf("completion retry = %v", err)
	}
	snapshot, err := registry.RecoverySnapshot(context.Background())
	if err != nil || len(snapshot.EpochFloors) != 1 || snapshot.EpochFloors[0].Epoch != first.SessionEpoch+9 {
		t.Fatalf("restored recovery snapshot = %#v, %v", snapshot, err)
	}
	next, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 2))
	if err != nil {
		t.Fatal(err)
	}
	if next.SessionEpoch != first.SessionEpoch+10 {
		t.Fatalf("restore floor ignored: got %d", next.SessionEpoch)
	}
}

func TestRecoverySnapshotIsCompleteSortedAndFenced(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)}
	path := filepath.Join(t.TempDir(), "identity.db")
	registry, err := Open(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	first := bootstrapRequest(t, clock.read(), 1)
	second := bootstrapRequest(t, clock.read(), 2)
	second.Session.TenantID = "tenant-b"
	if _, err := registry.ReserveBootstrap(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ReserveBootstrap(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.RecoverySnapshot(context.Background())
	if err != nil || len(snapshot.EpochFloors) != 2 || snapshot.EpochFloors[0].TenantID > snapshot.EpochFloors[1].TenantID {
		t.Fatalf("snapshot = %#v, %v", snapshot, err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	registry, err = OpenRestored(path, clock.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	if _, err := registry.RecoverySnapshot(context.Background()); !errors.Is(err, identity.ErrRegistryFenced) {
		t.Fatalf("fenced snapshot = %v", err)
	}
}

func TestProofCleanupIsBoundedAndStrictlyPastWindow(t *testing.T) {
	registry, clock := openTestRegistry(t)
	pending, err := registry.ReserveBootstrap(context.Background(), bootstrapRequest(t, clock.read(), 1))
	if err != nil {
		t.Fatal(err)
	}
	clock.set(clock.read().Add(proofPastWindow))
	if count, err := registry.CleanupProofs(context.Background()); err != nil || count != 0 {
		t.Fatalf("proof removed at acceptance boundary: %d, %v", count, err)
	}
	clock.set(clock.read().Add(2 * time.Millisecond))
	if count, err := registry.CleanupProofs(context.Background()); err != nil || count != 1 {
		t.Fatalf("expired proof cleanup = %d, %v", count, err)
	}
	_ = pending
}

func TestSchemaContainsNoSecretBearingColumns(t *testing.T) {
	registry, _ := openTestRegistry(t)
	for _, table := range []string{"identity_metadata", "principal_epochs", "sessions", "proof_replays", "restore_epoch_floors"} {
		rows, err := registry.db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, kind string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"token", "proof", "subject", "jwt", "jwk", "claims"} {
				if name == forbidden || name == "raw_"+forbidden {
					t.Fatalf("secret-bearing column %s.%s", table, name)
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	request := bootstrapRequest(t, time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC), 1)
	if _, err := registry.ReserveBootstrap(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.db.Exec("UPDATE sessions SET state = 'active' WHERE bootstrap_operation_id = ?", request.Session.BootstrapOperationID); err == nil {
		t.Fatal("schema admitted active state without activation receipt")
	}
}

func TestOpenAppliesExactDurabilityProfile(t *testing.T) {
	registry, _ := openTestRegistry(t)
	checks := map[string]string{"journal_mode": "wal", "synchronous": "2", "foreign_keys": "1", "busy_timeout": "5000"}
	for pragma, want := range checks {
		var got string
		if err := registry.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("PRAGMA %s = %q, want %q", pragma, got, want)
		}
	}
	var version int
	if err := registry.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
}

func TestOpenRejectsUnknownSchemaWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)}
	if _, err := Open(path, clock.read); !errors.Is(err, identity.ErrRegistryUnavailable) {
		t.Fatalf("unknown schema accepted: %v", err)
	}
	db, err = sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 99 {
		t.Fatalf("unknown schema mutated: %d, %v", version, err)
	}
}

func TestAbruptExitRecoversAndAbandonsPending(t *testing.T) {
	if os.Getenv("YUKH_IDENTITY_CRASH_HELPER") == "1" {
		path := os.Getenv("YUKH_IDENTITY_CRASH_PATH")
		now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
		registry, err := Open(path, func() time.Time { return now })
		if err != nil {
			panic(err)
		}
		request := fixedBootstrapRequest(now, 1)
		if _, err := registry.ReserveBootstrap(context.Background(), request); err != nil {
			panic(err)
		}
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "identity.db")
	command := exec.Command(os.Args[0], "-test.run=^TestAbruptExitRecoversAndAbandonsPending$")
	command.Env = append(os.Environ(), "YUKH_IDENTITY_CRASH_HELPER=1", "YUKH_IDENTITY_CRASH_PATH="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v\n%s", err, output)
	}
	now := time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)
	registry, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	first := fixedBootstrapRequest(now, 1)
	if _, err := registry.ActivateBootstrap(context.Background(), first.Session.BootstrapOperationID, "audit:late"); !errors.Is(err, identity.ErrSessionConflict) {
		t.Fatalf("crash-surviving pending session activated: %v", err)
	}
	second, err := registry.ReserveBootstrap(context.Background(), fixedBootstrapRequest(now, 2))
	if err != nil {
		t.Fatal(err)
	}
	if second.SessionEpoch != 2 {
		t.Fatalf("crash reused epoch: %d", second.SessionEpoch)
	}
}

func openTestRegistry(t *testing.T) (*Registry, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 8, 3, 8, 0, 0, 0, time.UTC)}
	registry, err := Open(filepath.Join(t.TempDir(), "identity.db"), clock.read)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return registry, clock
}

func bootstrapRequest(t *testing.T, now time.Time, discriminator byte) identity.BootstrapReservation {
	t.Helper()
	participant, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	operation, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return identity.BootstrapReservation{
		Session: identity.PendingSession{
			TenantID: "tenant:example", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ParticipantInstanceID: participant.String(), TokenDigest: digest(string([]byte{'t', discriminator})),
			DPoPThumbprint: digest(string([]byte{'d', discriminator})), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
			BootstrapOperationID: operation.String(),
		},
		ProofJTI: "bootstrapProof" + string([]byte{'A' + discriminator}) + "AB", ProofIAT: now,
	}
}

func digest(value string) [sha256.Size]byte { return sha256.Sum256([]byte(value)) }

func fixedBootstrapRequest(now time.Time, discriminator byte) identity.BootstrapReservation {
	participant := "01890f3e-7b00-7000-8000-00000000000" + string([]byte{'0' + discriminator})
	operation := "01890f3e-7b00-7000-9000-00000000000" + string([]byte{'0' + discriminator})
	return identity.BootstrapReservation{
		Session: identity.PendingSession{
			TenantID: "tenant:example", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ParticipantInstanceID: participant, TokenDigest: digest(string([]byte{'t', discriminator})),
			DPoPThumbprint: digest(string([]byte{'d', discriminator})), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
			BootstrapOperationID: operation,
		},
		ProofJTI: "fixedProofABCDEFG" + string([]byte{'A' + discriminator}), ProofIAT: now,
	}
}
