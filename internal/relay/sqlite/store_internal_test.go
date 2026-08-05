package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAppliesDurabilityProfile(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	checks := []struct {
		pragma string
		want   string
	}{
		{"journal_mode", "wal"},
		{"synchronous", "2"},
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
		{"user_version", "6"},
	}
	for _, check := range checks {
		t.Run(check.pragma, func(t *testing.T) {
			var got string
			if err := store.db.QueryRowContext(context.Background(), "PRAGMA "+check.pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != check.want {
				t.Fatalf("PRAGMA %s: got %q, want %q", check.pragma, got, check.want)
			}
		})
	}

	store.db.SetMaxIdleConns(0)
	store.db.SetMaxIdleConns(1)
	var foreignKeys string
	if err := store.db.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != "1" {
		t.Fatalf("replacement connection lost foreign-key enforcement: %q", foreignKeys)
	}
}

func TestOpenMigratesSchemaVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-one.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE accepted_records (id INTEGER) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE transcripts (id INTEGER) STRICT`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 6 {
		t.Fatalf("schema version: got %d, want 6", version)
	}
	rows, err := store.db.Query("PRAGMA table_info(accepted_records)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	foundColumns := map[string]bool{
		"signing_key_id":      false,
		"signature_algorithm": false,
		"signature":           false,
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if _, tracked := foundColumns[name]; tracked {
			foundColumns[name] = true
		}
	}
	for name, found := range foundColumns {
		if !found {
			t.Fatalf("version-one migration did not add %s column", name)
		}
	}
	metadataRows, err := store.db.Query("PRAGMA table_info(transcripts)")
	if err != nil {
		t.Fatal(err)
	}
	defer metadataRows.Close()
	foundMetadata := map[string]bool{"canonical_metadata": false, "metadata_digest": false, "lifecycle": false, "completeness": false}
	for metadataRows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := metadataRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if _, tracked := foundMetadata[name]; tracked {
			foundMetadata[name] = true
		}
	}
	for name, found := range foundMetadata {
		if !found {
			t.Fatalf("version-two migration did not add %s column", name)
		}
	}
	for _, table := range []string{"lifecycle_policies", "transcript_policy_bindings", "lifecycle_operations", "lifecycle_payload_tombstones", "lifecycle_identifier_tombstones", "lifecycle_backup_obligation_sets", "lifecycle_backup_obligations", "lifecycle_backup_receipts", "lifecycle_completions"} {
		var found string
		if err := store.db.QueryRow(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&found); err != nil {
			t.Fatalf("version-three migration did not create %s: %v", table, err)
		}
	}
	operationRows, err := store.db.Query("PRAGMA table_info(lifecycle_operations)")
	if err != nil {
		t.Fatal(err)
	}
	defer operationRows.Close()
	foundRemoval := map[string]bool{"receipt_signature": false, "payload_removal_digest": false}
	for operationRows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := operationRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if _, tracked := foundRemoval[name]; tracked {
			foundRemoval[name] = true
		}
	}
	for name, found := range foundRemoval {
		if !found {
			t.Fatalf("version-four migration did not add %s column", name)
		}
	}
}

func TestOpenRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "unsupported sqlite schema version 99") {
		t.Fatalf("expected unknown schema rejection, got %v", err)
	}
}

func TestOpenMigratesSchemaVersionFiveToSix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "version-five.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"lifecycle_completions", "lifecycle_backup_receipts", "lifecycle_backup_obligations", "lifecycle_backup_obligation_sets"} {
		if _, err := store.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec("PRAGMA user_version=5"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var version int
	if err := reopened.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 6 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	for _, table := range []string{"lifecycle_backup_obligation_sets", "lifecycle_backup_obligations", "lifecycle_backup_receipts", "lifecycle_completions"} {
		var found string
		if err := reopened.db.QueryRow(`SELECT name FROM sqlite_schema WHERE type='table' AND name=?`, table).Scan(&found); err != nil {
			t.Fatalf("missing %s: %v", table, err)
		}
	}
}
