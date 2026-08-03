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
		{"user_version", "2"},
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
	if version != 2 {
		t.Fatalf("schema version: got %d, want 2", version)
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
