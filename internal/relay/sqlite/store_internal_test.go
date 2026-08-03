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
		{"user_version", "1"},
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
