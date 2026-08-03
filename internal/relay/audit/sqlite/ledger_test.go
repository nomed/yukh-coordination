package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
	_ "modernc.org/sqlite"
)

func TestAppendExactRetryConflictAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ledger := openLedger(t, path)
	record := testRecord(t, 1)
	first, err := ledger.Append(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := ledger.Append(context.Background(), record)
	if err != nil || retry != first {
		t.Fatalf("retry = %#v, %v; want %#v", retry, err, first)
	}
	changed := record
	changed.DecisionTime = changed.DecisionTime.Add(time.Millisecond)
	if _, err := ledger.Append(context.Background(), changed); !errors.Is(err, audit.ErrConflict) {
		t.Fatalf("changed retry = %v, want conflict", err)
	}
	var count int
	if err := ledger.db.QueryRow("SELECT COUNT(*) FROM audit_entries").Scan(&count); err != nil || count != 1 {
		t.Fatalf("entry count = %d, %v", count, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	got, err := ledger.Append(context.Background(), record)
	if err != nil || got != first {
		t.Fatalf("restart retry = %#v, %v; want %#v", got, err, first)
	}
}

func TestConcurrentAppendsAreGapFreeAndIdempotent(t *testing.T) {
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	const records = 24
	var group sync.WaitGroup
	errs := make(chan error, records*2)
	for i := 1; i <= records; i++ {
		record := testRecord(t, i)
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				_, err := ledger.Append(context.Background(), record)
				errs <- err
			}()
		}
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := ledger.db.Query("SELECT sequence FROM audit_entries ORDER BY sequence")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var expected uint64 = 1
	for rows.Next() {
		var sequence uint64
		if err := rows.Scan(&sequence); err != nil || sequence != expected {
			t.Fatalf("sequence = %d, %v; want %d", sequence, err, expected)
		}
		expected++
	}
	if err := rows.Err(); err != nil || expected != records+1 {
		t.Fatalf("rows = %v, next sequence = %d", err, expected)
	}
	if err := ledger.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaIsStrictImmutableAndConfigured(t *testing.T) {
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	if _, err := ledger.Append(context.Background(), testRecord(t, 1)); err != nil {
		t.Fatal(err)
	}
	var version int
	var journal, synchronous string
	if err := ledger.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if err := ledger.db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal = %q, %v", journal, err)
	}
	if err := ledger.db.QueryRow("PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != "2" {
		t.Fatalf("synchronous = %q, %v", synchronous, err)
	}
	if _, err := ledger.db.Exec("UPDATE audit_entries SET canonical_record = canonical_record WHERE sequence = 1"); err == nil {
		t.Fatal("immutable entry updated")
	}
	if _, err := ledger.db.Exec("DELETE FROM audit_entries WHERE sequence = 1"); err == nil {
		t.Fatal("immutable entry deleted")
	}
	if _, err := ledger.db.Exec("UPDATE audit_metadata SET chain_head = zeroblob(32) WHERE singleton = 1"); err == nil {
		t.Fatal("invalid metadata transition accepted")
	}
	if _, err := ledger.db.Exec("DELETE FROM audit_metadata WHERE singleton = 1"); err == nil {
		t.Fatal("audit metadata deleted")
	}
	if _, err := ledger.db.Exec("INSERT INTO audit_entries(sequence) VALUES ('wrong')"); err == nil {
		t.Fatal("STRICT schema admitted invalid row")
	}
}

func TestOpenRejectsTamperedChainAndUnsupportedSchema(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE audit_metadata SET chain_head = zeroblob(32) WHERE singleton = 1",
		"UPDATE audit_entries SET canonical_record = x'7b7d' WHERE sequence = 1",
		"DELETE FROM audit_entries WHERE sequence = 1",
	} {
		t.Run(fmt.Sprintf("mutation-%x", sha256.Sum256([]byte(mutation)))[:20], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			ledger := openLedger(t, path)
			if _, err := ledger.Append(context.Background(), testRecord(t, 1)); err != nil {
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			db := rawDB(t, path)
			for _, trigger := range []string{"audit_entries_no_update", "audit_entries_no_delete", "audit_metadata_append_only", "audit_metadata_no_delete"} {
				if _, err := db.Exec("DROP TRIGGER " + trigger); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			_ = db.Close()
			if opened, err := Open(path); err == nil {
				_ = opened.Close()
				t.Fatal("tampered ledger opened")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "future.db")
	db := rawDB(t, path)
	if _, err := db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if opened, err := Open(path); err == nil {
		_ = opened.Close()
		t.Fatal("unsupported schema opened")
	}
}

func TestAuditorPortReturnsBoundedReference(t *testing.T) {
	ledger := openLedger(t, filepath.Join(t.TempDir(), "audit.db"))
	var port identity.Auditor = ledger
	reference, err := port.Record(context.Background(), testRecord(t, 1))
	if err != nil || len(reference) > 256 {
		t.Fatalf("reference = %q, %v", reference, err)
	}
	if err := port.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func openLedger(t *testing.T, path string) *Ledger {
	t.Helper()
	ledger, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return ledger
}

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func testRecord(t *testing.T, index int) identity.AuditRecord {
	t.Helper()
	operationID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	participantID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	principal := sha256.Sum256([]byte(fmt.Sprintf("principal-%d", index)))
	thumbprint := sha256.Sum256([]byte(fmt.Sprintf("thumbprint-%d", index)))
	return identity.AuditRecord{
		ProfileVersion: 1, OperationID: operationID.String(), Operation: identity.AuditBootstrap,
		Outcome: identity.AuditAllow, Reason: identity.AuditReasonAllowed,
		DecisionTime: time.Date(2026, 8, 3, 9, 0, 0, index*int(time.Millisecond), time.UTC),
		TenantID:     "tenant-a", PrincipalID: base64.RawURLEncoding.EncodeToString(principal[:]),
		ParticipantInstanceID: participantID.String(), SessionEpoch: uint64(index),
		DPoPThumbprint: thumbprint, HasDPoPThumbprint: true,
	}
}
