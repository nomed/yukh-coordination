package primitivesstaging

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const replaySchemaVersion = 1

type ReplayStore struct {
	db         *sql.DB
	maxEntries int
	closeOnce  sync.Once
}

func OpenReplayStore(path string, maxEntries int, now time.Time) (*ReplayStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maxEntries < 1 || maxEntries > 100_000 || !validMillisecond(now) || !secureParent(path) {
		return nil, ErrInvalid
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return nil, ErrInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrInvalid
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "_busy_timeout=5000&_journal_mode=wal&_synchronous=full"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &ReplayStore{db: db, maxEntries: maxEntries}
	if err := store.initialize(context.Background(), now); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *ReplayStore) initialize(ctx context.Context, now time.Time) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var version int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version < 0 || version > replaySchemaVersion {
		return ErrUnavailable
	}
	if version == 0 {
		statements := []string{
			`CREATE TABLE replay_metadata (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), schema_version INTEGER NOT NULL CHECK (schema_version = 1), wall_high_water_ms INTEGER NOT NULL CHECK (wall_high_water_ms >= 0 AND wall_high_water_ms <= 9007199254740991)) STRICT`,
			`CREATE TABLE proof_replays (thumbprint BLOB NOT NULL CHECK (length(thumbprint) = 32), proof_jti TEXT NOT NULL CHECK (length(proof_jti) BETWEEN 16 AND 128 AND proof_jti NOT GLOB '*[^A-Za-z0-9_-]*'), issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0 AND issued_at_ms <= 9007199254740991), retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > issued_at_ms AND retain_until_ms <= 9007199254740991), PRIMARY KEY (thumbprint, proof_jti)) STRICT`,
			`CREATE INDEX proof_replays_retention ON proof_replays (retain_until_ms)`,
			`INSERT INTO replay_metadata VALUES (1, 1, ?)`,
			`PRAGMA user_version = 1`,
		}
		for _, statement := range statements {
			if statement == `INSERT INTO replay_metadata VALUES (1, 1, ?)` {
				_, err = conn.ExecContext(ctx, statement, now.UnixMilli())
			} else {
				_, err = conn.ExecContext(ctx, statement)
			}
			if err != nil {
				return ErrUnavailable
			}
		}
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return ErrUnavailable
	}
	committed = true
	return nil
}

func (s *ReplayStore) Reserve(ctx context.Context, thumbprint [sha256.Size]byte, jti string, issuedAt, now time.Time) error {
	if s == nil || s.db == nil || !base64urlRange(jti, 16, 128) || !validMillisecond(now) || issuedAt.IsZero() {
		return ErrUnavailable
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return ErrUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var highWater, count int64
	if err = conn.QueryRowContext(ctx, "SELECT wall_high_water_ms FROM replay_metadata WHERE singleton = 1 AND schema_version = 1").Scan(&highWater); err != nil || now.UnixMilli() < highWater-5_000 {
		return ErrUnavailable
	}
	if now.UnixMilli() > highWater {
		if _, err = conn.ExecContext(ctx, "UPDATE replay_metadata SET wall_high_water_ms = ? WHERE singleton = 1", now.UnixMilli()); err != nil {
			return ErrUnavailable
		}
	}
	if _, err = conn.ExecContext(ctx, "DELETE FROM proof_replays WHERE rowid IN (SELECT rowid FROM proof_replays WHERE retain_until_ms <= ? ORDER BY retain_until_ms LIMIT 256)", now.UnixMilli()); err != nil {
		return ErrUnavailable
	}
	if err = conn.QueryRowContext(ctx, "SELECT count(*) FROM proof_replays").Scan(&count); err != nil || count >= int64(s.maxEntries) {
		return ErrUnavailable
	}
	retainUntil := issuedAt.Add(65 * time.Second).UnixMilli()
	if retainUntil <= now.UnixMilli() {
		retainUntil = now.Add(5 * time.Second).UnixMilli()
	}
	if _, err = conn.ExecContext(ctx, "INSERT INTO proof_replays (thumbprint, proof_jti, issued_at_ms, retain_until_ms) VALUES (?, ?, ?, ?)", thumbprint[:], jti, issuedAt.UnixMilli(), retainUntil); err != nil {
		var exists int
		if queryErr := conn.QueryRowContext(ctx, "SELECT 1 FROM proof_replays WHERE thumbprint = ? AND proof_jti = ?", thumbprint[:], jti).Scan(&exists); queryErr == nil {
			return ErrReplay
		}
		return ErrUnavailable
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return ErrUnavailable
	}
	committed = true
	return nil
}

func (s *ReplayStore) Ready(now time.Time) bool {
	if s == nil || s.db == nil || !validMillisecond(now) {
		return false
	}
	var version int
	var highWater int64
	err := s.db.QueryRow("SELECT schema_version, wall_high_water_ms FROM replay_metadata WHERE singleton = 1").Scan(&version, &highWater)
	return err == nil && version == replaySchemaVersion && now.UnixMilli() >= highWater-5_000
}

func (s *ReplayStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.db.Close() })
	return err
}

func (*ReplayStore) String() string               { return "ReplayStore{REDACTED}" }
func (*ReplayStore) GoString() string             { return "ReplayStore{REDACTED}" }
func (*ReplayStore) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
