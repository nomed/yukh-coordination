// Package sqlite implements the isolated durable identity registry selected by
// RFC-0010. It does not implement authentication policy, audit or HTTP wiring.
package sqlite

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
	_ "modernc.org/sqlite"
)

const (
	schemaVersion   = 2
	maxJSONSafeInt  = uint64(9_007_199_254_740_991)
	clockTolerance  = 5 * time.Second
	proofPastWindow = 60 * time.Second
	cleanupBatch    = 256
)

var (
	tenantPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,255}$`)
	closedText    = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	referenceText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

type Clock func() time.Time

type Registry struct {
	db  *sql.DB
	now Clock

	lifecycleMu sync.Mutex
	watchers    map[identity.SessionKey]map[chan struct{}]struct{}
	wakeExpiry  chan struct{}
	stopExpiry  chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
}

func Open(path string, now Clock) (*Registry, error) {
	return open(path, now, false)
}

// OpenRestored opens a restored database and durably fences it before any
// caller can use session state. A verified floor import is required to admit it.
func OpenRestored(path string, now Clock) (*Registry, error) {
	return open(path, now, true)
}

func open(path string, now Clock, restored bool) (*Registry, error) {
	if path == "" || now == nil {
		return nil, identity.ErrRegistryInvalid
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, identity.ErrRegistryUnavailable
	}
	dsn := (&url.URL{Scheme: "file", Path: absolutePath, RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=wal&_synchronous=full"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, identity.ErrRegistryUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	registry := &Registry{
		db: db, now: now, watchers: make(map[identity.SessionKey]map[chan struct{}]struct{}),
		wakeExpiry: make(chan struct{}, 1), stopExpiry: make(chan struct{}), closed: make(chan struct{}),
	}
	if err := registry.configure(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := registry.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := registry.startup(context.Background(), restored); err != nil {
		_ = db.Close()
		return nil, err
	}
	go registry.expiryLoop()
	return registry, nil
}

func (r *Registry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	var closeErr error
	r.closeOnce.Do(func() {
		close(r.stopExpiry)
		<-r.closed
		r.lifecycleMu.Lock()
		for key := range r.watchers {
			r.closeWatchersLocked(key)
		}
		r.lifecycleMu.Unlock()
		closeErr = r.db.Close()
	})
	return closeErr
}

func (r *Registry) configure(ctx context.Context) error {
	var journal string
	if err := r.db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		return identity.ErrRegistryUnavailable
	}
	for _, statement := range []string{"PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := r.db.ExecContext(ctx, statement); err != nil {
			return identity.ErrRegistryUnavailable
		}
	}
	return nil
}

func (r *Registry) migrate(ctx context.Context) error {
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	var version int
	if err := tx.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version < 0 || version > schemaVersion {
		return identity.ErrRegistryUnavailable
	}
	if version == schemaVersion {
		return tx.commit(ctx)
	}
	if version == 0 {
		statements := []string{
			`CREATE TABLE identity_metadata (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			profile_version INTEGER NOT NULL CHECK (profile_version = 1),
			database_id TEXT NOT NULL CHECK (length(database_id) = 36),
			wall_high_water_ms INTEGER NOT NULL CHECK (wall_high_water_ms >= 0 AND wall_high_water_ms <= 9007199254740991),
			fence_state TEXT NOT NULL CHECK (fence_state IN ('admitted', 'restore_fenced', 'clock_fenced')),
			fence_receipt TEXT CHECK (fence_receipt IS NULL OR (length(fence_receipt) BETWEEN 1 AND 256 AND fence_receipt NOT GLOB '*[^A-Za-z0-9._:/-]*'))
		) STRICT`,
			`CREATE TABLE principal_epochs (
			tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256 AND tenant_id GLOB '[a-z0-9]*' AND tenant_id NOT GLOB '*[^a-z0-9._:-]*'),
			principal_id TEXT NOT NULL CHECK (length(principal_id) = 43 AND principal_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			last_epoch INTEGER NOT NULL CHECK (last_epoch > 0 AND last_epoch <= 9007199254740991),
			PRIMARY KEY (tenant_id, principal_id)
		) STRICT`,
			`CREATE TABLE sessions (
			tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256 AND tenant_id GLOB '[a-z0-9]*' AND tenant_id NOT GLOB '*[^a-z0-9._:-]*'),
			principal_id TEXT NOT NULL CHECK (length(principal_id) = 43 AND principal_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			participant_instance_id TEXT NOT NULL CHECK (participant_instance_id GLOB '????????-????-7???-[89ab]???-????????????' AND participant_instance_id NOT GLOB '*[^0-9a-f-]*'),
			session_epoch INTEGER NOT NULL CHECK (session_epoch > 0 AND session_epoch <= 9007199254740991),
			token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
			dpop_thumbprint BLOB NOT NULL CHECK (length(dpop_thumbprint) = 32),
			issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0 AND issued_at_ms <= 9007199254740991),
			expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > issued_at_ms AND expires_at_ms <= 9007199254740991),
			state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked', 'expired', 'abandoned')),
			bootstrap_operation_id TEXT NOT NULL CHECK (bootstrap_operation_id GLOB '????????-????-7???-[89ab]???-????????????' AND bootstrap_operation_id NOT GLOB '*[^0-9a-f-]*'),
			activation_receipt TEXT CHECK (activation_receipt IS NULL OR (length(activation_receipt) BETWEEN 1 AND 256 AND activation_receipt NOT GLOB '*[^A-Za-z0-9._:/-]*')),
			revoked_at_ms INTEGER CHECK (revoked_at_ms IS NULL OR (revoked_at_ms >= issued_at_ms AND revoked_at_ms <= 9007199254740991)),
			revocation_reason TEXT CHECK (revocation_reason IS NULL OR (length(revocation_reason) BETWEEN 1 AND 128 AND revocation_reason NOT GLOB '*[^a-z0-9._:-]*')),
			revocation_authority TEXT CHECK (revocation_authority IS NULL OR (length(revocation_authority) BETWEEN 1 AND 256 AND revocation_authority NOT GLOB '*[^A-Za-z0-9._:/-]*')),
			CHECK (
				(state IN ('pending', 'abandoned') AND activation_receipt IS NULL AND revoked_at_ms IS NULL AND revocation_reason IS NULL AND revocation_authority IS NULL) OR
				(state IN ('active', 'expired') AND activation_receipt IS NOT NULL AND revoked_at_ms IS NULL AND revocation_reason IS NULL AND revocation_authority IS NULL) OR
				(state = 'revoked' AND activation_receipt IS NOT NULL AND revoked_at_ms IS NOT NULL AND revocation_reason IS NOT NULL AND revocation_authority IS NOT NULL)
			),
			PRIMARY KEY (tenant_id, participant_instance_id),
			UNIQUE (participant_instance_id),
			UNIQUE (token_digest),
			UNIQUE (bootstrap_operation_id),
			UNIQUE (tenant_id, principal_id, session_epoch)
		) STRICT`,
			`CREATE TABLE proof_replays (
			jwk_thumbprint BLOB NOT NULL CHECK (length(jwk_thumbprint) = 32),
			proof_jti TEXT NOT NULL CHECK (length(proof_jti) BETWEEN 16 AND 128 AND proof_jti NOT GLOB '*[^A-Za-z0-9_-]*'),
			purpose TEXT NOT NULL CHECK (purpose IN ('bootstrap', 'authentication')),
			issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0 AND issued_at_ms <= 9007199254740991),
			retain_until_ms INTEGER NOT NULL CHECK (retain_until_ms > issued_at_ms AND retain_until_ms <= 9007199254740991),
			participant_instance_id TEXT NOT NULL CHECK (participant_instance_id GLOB '????????-????-7???-[89ab]???-????????????' AND participant_instance_id NOT GLOB '*[^0-9a-f-]*'),
			PRIMARY KEY (jwk_thumbprint, proof_jti),
			FOREIGN KEY (participant_instance_id) REFERENCES sessions (participant_instance_id)
		) STRICT`,
			`CREATE INDEX proof_replays_retention ON proof_replays (retain_until_ms)`,
			`CREATE TABLE restore_epoch_floors (
			tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256 AND tenant_id GLOB '[a-z0-9]*' AND tenant_id NOT GLOB '*[^a-z0-9._:-]*'),
			principal_id TEXT NOT NULL CHECK (length(principal_id) = 43 AND principal_id NOT GLOB '*[^A-Za-z0-9_-]*'),
			epoch_floor INTEGER NOT NULL CHECK (epoch_floor > 0 AND epoch_floor <= 9007199254740991),
			checkpoint_receipt TEXT NOT NULL CHECK (length(checkpoint_receipt) BETWEEN 1 AND 256 AND checkpoint_receipt NOT GLOB '*[^A-Za-z0-9._:/-]*'),
			PRIMARY KEY (tenant_id, principal_id)
		) STRICT`,
		}
		for _, statement := range statements {
			if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
				return identity.ErrRegistryUnavailable
			}
		}
		databaseID, err := uuid.NewV7()
		if err != nil {
			return identity.ErrRegistryUnavailable
		}
		nowMS, ok := unixMillis(r.now())
		if !ok {
			return identity.ErrRegistryUnavailable
		}
		if _, err := tx.conn.ExecContext(ctx, "INSERT INTO identity_metadata VALUES (1, 1, ?, ?, 'admitted', NULL)", databaseID.String(), nowMS); err != nil {
			return identity.ErrRegistryUnavailable
		}
		version = 1
	}
	if version == 1 {
		if _, err := tx.conn.ExecContext(ctx, `ALTER TABLE sessions ADD COLUMN revocation_operation_id TEXT CHECK (revocation_operation_id IS NULL OR (revocation_operation_id GLOB '????????-????-7???-[89ab]???-????????????' AND revocation_operation_id NOT GLOB '*[^0-9a-f-]*'))`); err != nil {
			return identity.ErrRegistryUnavailable
		}
		if _, err := tx.conn.ExecContext(ctx, `ALTER TABLE restore_epoch_floors RENAME COLUMN checkpoint_receipt TO recovery_reference`); err != nil {
			return identity.ErrRegistryUnavailable
		}
		version = 2
	}
	if version != schemaVersion {
		return identity.ErrRegistryUnavailable
	}
	if _, err := tx.conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		return identity.ErrRegistryUnavailable
	}
	return tx.commit(ctx)
}

func (r *Registry) startup(ctx context.Context, restored bool) error {
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	nowMS, ok := unixMillis(r.now())
	if !ok {
		return identity.ErrRegistryUnavailable
	}
	var high int64
	if err := tx.conn.QueryRowContext(ctx, "SELECT wall_high_water_ms FROM identity_metadata WHERE singleton = 1").Scan(&high); err != nil {
		return identity.ErrRegistryUnavailable
	}
	if restored {
		if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET fence_state = 'restore_fenced', fence_receipt = NULL WHERE singleton = 1"); err != nil {
			return identity.ErrRegistryUnavailable
		}
	} else if nowMS < high-clockTolerance.Milliseconds() {
		if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET fence_state = 'clock_fenced', fence_receipt = NULL WHERE singleton = 1"); err != nil {
			return identity.ErrRegistryUnavailable
		}
	} else if nowMS > high {
		if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET wall_high_water_ms = ? WHERE singleton = 1", nowMS); err != nil {
			return identity.ErrRegistryUnavailable
		}
	}
	if _, err := tx.conn.ExecContext(ctx, "UPDATE sessions SET state = 'abandoned' WHERE state = 'pending'"); err != nil {
		return identity.ErrRegistryUnavailable
	}
	var invalidRevocations uint64
	if err := tx.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE (state = 'revoked' AND revocation_operation_id IS NULL) OR (state != 'revoked' AND revocation_operation_id IS NOT NULL)`).Scan(&invalidRevocations); err != nil || invalidRevocations != 0 {
		return identity.ErrRegistryUnavailable
	}
	return tx.commit(ctx)
}

func (r *Registry) Status(ctx context.Context) (identity.RegistryStatus, error) {
	if err := contextError(ctx); err != nil {
		return identity.RegistryStatus{}, err
	}
	var result identity.RegistryStatus
	var high int64
	if err := r.db.QueryRowContext(ctx, "SELECT database_id, fence_state, wall_high_water_ms FROM identity_metadata WHERE singleton = 1").Scan(&result.DatabaseID, &result.FenceState, &high); err != nil {
		return identity.RegistryStatus{}, identity.ErrRegistryUnavailable
	}
	result.SchemaVersion = schemaVersion
	result.WallHighWater = time.UnixMilli(high).UTC()
	return result, nil
}

// RecoverySnapshot returns the complete deterministic epoch high-water set
// required by RFC-0010 recovery manifests. It never returns a partial set or
// admits a fenced registry.
func (r *Registry) RecoverySnapshot(ctx context.Context) (identity.RecoverySnapshot, error) {
	if err := contextError(ctx); err != nil {
		return identity.RecoverySnapshot{}, err
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
	}
	defer tx.rollback()
	var databaseID, fence string
	var high int64
	if err := tx.conn.QueryRowContext(ctx, `SELECT database_id, fence_state, wall_high_water_ms FROM identity_metadata WHERE singleton = 1`).Scan(&databaseID, &fence, &high); err != nil {
		return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
	}
	if fence != "admitted" {
		return identity.RecoverySnapshot{}, identity.ErrRegistryFenced
	}
	rows, err := tx.conn.QueryContext(ctx, `SELECT tenant_id, principal_id, MAX(epoch) FROM (
		SELECT tenant_id, principal_id, last_epoch AS epoch FROM principal_epochs
		UNION ALL
		SELECT tenant_id, principal_id, epoch_floor AS epoch FROM restore_epoch_floors
	) GROUP BY tenant_id, principal_id ORDER BY tenant_id, principal_id`)
	if err != nil {
		return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
	}
	result := identity.RecoverySnapshot{DatabaseID: databaseID, WallHighWater: time.UnixMilli(high).UTC()}
	for rows.Next() {
		var floor identity.EpochFloor
		if rows.Scan(&floor.TenantID, &floor.PrincipalID, &floor.Epoch) != nil || len(result.EpochFloors) >= 100_000 {
			return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
		}
		result.EpochFloors = append(result.EpochFloors, floor)
	}
	if rows.Err() != nil {
		return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
	}
	if rows.Close() != nil || tx.commit(ctx) != nil {
		return identity.RecoverySnapshot{}, identity.ErrRegistryUnavailable
	}
	return result, nil
}

func (r *Registry) ReserveBootstrap(ctx context.Context, request identity.BootstrapReservation) (identity.PendingSession, error) {
	if err := validateBootstrap(request); err != nil {
		return identity.PendingSession{}, err
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return identity.PendingSession{}, err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return identity.PendingSession{}, finishClockFailure(ctx, tx, clockErr)
	}
	if request.Session.ExpiresAt.UnixMilli() <= nowMS {
		return identity.PendingSession{}, identity.ErrRegistryInvalid
	}
	if collision, err := hasSessionCollision(ctx, tx.conn, request.Session); err != nil {
		return identity.PendingSession{}, err
	} else if collision {
		return identity.PendingSession{}, identity.ErrSessionConflict
	}
	epoch, err := allocateEpoch(ctx, tx, request.Session.TenantID, request.Session.PrincipalID)
	if err != nil {
		return identity.PendingSession{}, err
	}
	request.Session.SessionEpoch = epoch
	_, err = tx.conn.ExecContext(ctx, `INSERT INTO sessions
		(tenant_id, principal_id, participant_instance_id, session_epoch, token_digest, dpop_thumbprint, issued_at_ms, expires_at_ms, state, bootstrap_operation_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
		request.Session.TenantID, request.Session.PrincipalID, request.Session.ParticipantInstanceID, epoch,
		request.Session.TokenDigest[:], request.Session.DPoPThumbprint[:], request.Session.IssuedAt.UnixMilli(), request.Session.ExpiresAt.UnixMilli(), request.Session.BootstrapOperationID)
	if err != nil {
		return identity.PendingSession{}, identity.ErrRegistryUnavailable
	}
	if err := reserveProof(ctx, tx, request.Session.DPoPThumbprint, request.ProofJTI, identity.ProofBootstrap, request.ProofIAT, request.Session.ParticipantInstanceID); err != nil {
		return identity.PendingSession{}, err
	}
	if err := tx.commit(ctx); err != nil {
		return identity.PendingSession{}, err
	}
	return request.Session, nil
}

func (r *Registry) ActivateBootstrap(ctx context.Context, operationID, receipt string) (identity.ActiveSession, error) {
	if !validUUIDv7(operationID) || !referenceText.MatchString(receipt) {
		return identity.ActiveSession{}, identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return identity.ActiveSession{}, err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return identity.ActiveSession{}, finishClockFailure(ctx, tx, clockErr)
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE sessions SET state = 'active', activation_receipt = ?
		WHERE bootstrap_operation_id = ? AND state = 'pending' AND expires_at_ms > ?`, receipt, operationID, nowMS)
	if err != nil {
		return identity.ActiveSession{}, identity.ErrRegistryUnavailable
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		var state, existingReceipt string
		err := tx.conn.QueryRowContext(ctx, "SELECT state, COALESCE(activation_receipt, '') FROM sessions WHERE bootstrap_operation_id = ?", operationID).Scan(&state, &existingReceipt)
		if err == nil && state == string(identity.SessionActive) && existingReceipt == receipt {
			session, lookupErr := activeByOperation(ctx, tx.conn, operationID)
			if lookupErr != nil {
				return identity.ActiveSession{}, lookupErr
			}
			if err := tx.commit(ctx); err != nil {
				return identity.ActiveSession{}, err
			}
			return session, nil
		}
		return identity.ActiveSession{}, identity.ErrSessionConflict
	}
	session, err := activeByOperation(ctx, tx.conn, operationID)
	if err != nil {
		return identity.ActiveSession{}, err
	}
	if err := tx.commit(ctx); err != nil {
		return identity.ActiveSession{}, err
	}
	r.wakeScheduler()
	return session, nil
}

func (r *Registry) Authenticate(ctx context.Context, request identity.AuthenticationReservation) (identity.ActiveSession, error) {
	if !validProof(request.ProofJTI, request.ProofIAT) || request.TokenDigest == ([sha256.Size]byte{}) || request.DPoPThumbprint == ([sha256.Size]byte{}) {
		return identity.ActiveSession{}, identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return identity.ActiveSession{}, err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return identity.ActiveSession{}, finishClockFailure(ctx, tx, clockErr)
	}
	var session identity.ActiveSession
	var storedDigest, thumbprint []byte
	var expiry int64
	err = tx.conn.QueryRowContext(ctx, `SELECT tenant_id, principal_id, participant_instance_id, session_epoch, token_digest, dpop_thumbprint, expires_at_ms
		FROM sessions WHERE token_digest = ? AND state = 'active' AND expires_at_ms > ?`, request.TokenDigest[:], nowMS).Scan(
		&session.TenantID, &session.PrincipalID, &session.ParticipantInstanceID, &session.SessionEpoch, &storedDigest, &thumbprint, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.ActiveSession{}, identity.ErrSessionNotFound
	}
	if err != nil || len(storedDigest) != sha256.Size || len(thumbprint) != sha256.Size {
		return identity.ActiveSession{}, identity.ErrRegistryUnavailable
	}
	copy(session.DPoPThumbprint[:], thumbprint)
	if subtle.ConstantTimeCompare(storedDigest, request.TokenDigest[:]) != 1 || subtle.ConstantTimeCompare(thumbprint, request.DPoPThumbprint[:]) != 1 {
		return identity.ActiveSession{}, identity.ErrSessionNotFound
	}
	session.ExpiresAt = time.UnixMilli(expiry).UTC()
	if err := reserveProof(ctx, tx, request.DPoPThumbprint, request.ProofJTI, identity.ProofAuthentication, request.ProofIAT, session.ParticipantInstanceID); err != nil {
		return identity.ActiveSession{}, err
	}
	if err := tx.commit(ctx); err != nil {
		return identity.ActiveSession{}, err
	}
	return session, nil
}

func (r *Registry) Revoke(ctx context.Context, request identity.Revocation) error {
	if !validUUID(request.OperationID) || !validSessionKey(request.Key) || !closedText.MatchString(request.Reason) || !referenceText.MatchString(request.AuthorityReceipt) {
		return identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return finishClockFailure(ctx, tx, clockErr)
	}
	result, err := tx.conn.ExecContext(ctx, `UPDATE sessions SET state = 'revoked', revoked_at_ms = ?, revocation_reason = ?, revocation_authority = ?, revocation_operation_id = ?
		WHERE tenant_id = ? AND participant_instance_id = ? AND session_epoch = ? AND state = 'active' AND expires_at_ms > ?`,
		nowMS, request.Reason, request.AuthorityReceipt, request.OperationID, request.Key.TenantID, request.Key.ParticipantInstanceID, request.Key.SessionEpoch, nowMS)
	if err != nil {
		return identity.ErrRegistryUnavailable
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		var state, reason, authority, operationID string
		if err := tx.conn.QueryRowContext(ctx, `SELECT state, COALESCE(revocation_reason, ''), COALESCE(revocation_authority, ''), COALESCE(revocation_operation_id, '') FROM sessions WHERE tenant_id = ? AND participant_instance_id = ? AND session_epoch = ?`, request.Key.TenantID, request.Key.ParticipantInstanceID, request.Key.SessionEpoch).Scan(&state, &reason, &authority, &operationID); err != nil || state != string(identity.SessionRevoked) || reason != request.Reason || authority != request.AuthorityReceipt || operationID != request.OperationID {
			return identity.ErrSessionConflict
		}
		return tx.commit(ctx)
	}
	if err := tx.commit(ctx); err != nil {
		return err
	}
	r.notifyInactive(request.Key)
	r.wakeScheduler()
	return nil
}

func (r *Registry) IsActive(ctx context.Context, key identity.SessionKey) (bool, error) {
	if !validSessionKey(key) {
		return false, identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return false, err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return false, finishClockFailure(ctx, tx, clockErr)
	}
	var state string
	var expires int64
	err = tx.conn.QueryRowContext(ctx, `SELECT state, expires_at_ms FROM sessions
		WHERE tenant_id = ? AND participant_instance_id = ? AND session_epoch = ?`, key.TenantID, key.ParticipantInstanceID, key.SessionEpoch).Scan(&state, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return false, identity.ErrSessionNotFound
	}
	if err != nil {
		return false, identity.ErrRegistryUnavailable
	}
	if state == string(identity.SessionActive) && expires <= nowMS {
		if _, err := tx.conn.ExecContext(ctx, `UPDATE sessions SET state = 'expired' WHERE tenant_id = ? AND participant_instance_id = ? AND session_epoch = ? AND state = 'active'`, key.TenantID, key.ParticipantInstanceID, key.SessionEpoch); err != nil {
			return false, identity.ErrRegistryUnavailable
		}
		state = string(identity.SessionExpired)
	}
	if err := tx.commit(ctx); err != nil {
		return false, err
	}
	if state != string(identity.SessionActive) {
		r.notifyInactive(key)
	}
	return state == string(identity.SessionActive), nil
}

// SubscribeInactive registers before checking durable state, so a concurrent
// revoke is observed either by the durable read or by the signal close.
func (r *Registry) SubscribeInactive(ctx context.Context, key identity.SessionKey) (<-chan struct{}, error) {
	if err := contextError(ctx); err != nil || !validSessionKey(key) {
		return nil, identity.ErrRegistryInvalid
	}
	signal := make(chan struct{})
	r.lifecycleMu.Lock()
	if r.watchers[key] == nil {
		r.watchers[key] = make(map[chan struct{}]struct{})
	}
	r.watchers[key][signal] = struct{}{}
	r.lifecycleMu.Unlock()
	active, err := r.IsActive(ctx, key)
	if err != nil && !errors.Is(err, identity.ErrSessionNotFound) {
		r.removeWatcher(key, signal)
		return nil, err
	}
	if !active {
		r.notifyInactive(key)
	}
	return signal, nil
}

// StageRestoreFloors monotonically loads one complete verified recovery set but
// deliberately leaves the registry fenced. Admission requires a later audit
// receipt through CompleteRestore.
func (r *Registry) StageRestoreFloors(ctx context.Context, databaseID, manifestReference string, wallHighWater time.Time, floors []identity.EpochFloor) error {
	highWaterMS, ok := unixMillis(wallHighWater)
	if !ok || !validUUID(databaseID) || !referenceText.MatchString(manifestReference) || len(floors) > 100_000 {
		return identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	var actualID, fence string
	var high int64
	if err := tx.conn.QueryRowContext(ctx, "SELECT database_id, fence_state, wall_high_water_ms FROM identity_metadata WHERE singleton = 1").Scan(&actualID, &fence, &high); err != nil {
		return identity.ErrRegistryUnavailable
	}
	if actualID != databaseID || fence != "restore_fenced" {
		return identity.ErrRegistryFenced
	}
	if highWaterMS < high {
		return identity.ErrRegistryInvalid
	}
	nowMS, ok := unixMillis(r.now())
	if !ok || nowMS < highWaterMS-clockTolerance.Milliseconds() {
		return identity.ErrClockRollback
	}
	seen := make(map[string]struct{}, len(floors))
	for _, floor := range floors {
		key := floor.TenantID + "\x00" + floor.PrincipalID
		if !validTenant(floor.TenantID) || !validDigestText(floor.PrincipalID) || floor.Epoch == 0 || floor.Epoch > maxJSONSafeInt {
			return identity.ErrRegistryInvalid
		}
		if _, duplicate := seen[key]; duplicate {
			return identity.ErrRegistryInvalid
		}
		seen[key] = struct{}{}
		var liveEpoch uint64
		err := tx.conn.QueryRowContext(ctx, "SELECT last_epoch FROM principal_epochs WHERE tenant_id = ? AND principal_id = ?", floor.TenantID, floor.PrincipalID).Scan(&liveEpoch)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return identity.ErrRegistryUnavailable
		}
		if floor.Epoch < liveEpoch {
			return identity.ErrRegistryInvalid
		}
		var existingFloor uint64
		err = tx.conn.QueryRowContext(ctx, `SELECT epoch_floor FROM restore_epoch_floors WHERE tenant_id = ? AND principal_id = ?`, floor.TenantID, floor.PrincipalID).Scan(&existingFloor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return identity.ErrRegistryUnavailable
		}
		if err == nil && existingFloor > floor.Epoch {
			return identity.ErrRegistryInvalid
		}
		if _, err := tx.conn.ExecContext(ctx, `INSERT INTO restore_epoch_floors (tenant_id, principal_id, epoch_floor, recovery_reference)
			VALUES (?, ?, ?, ?) ON CONFLICT (tenant_id, principal_id) DO UPDATE SET
			epoch_floor = excluded.epoch_floor, recovery_reference = excluded.recovery_reference`, floor.TenantID, floor.PrincipalID, floor.Epoch, manifestReference); err != nil {
			return identity.ErrRegistryUnavailable
		}
	}
	rows, err := tx.conn.QueryContext(ctx, "SELECT tenant_id, principal_id FROM principal_epochs")
	if err != nil {
		return identity.ErrRegistryUnavailable
	}
	for rows.Next() {
		var tenant, principal string
		if err := rows.Scan(&tenant, &principal); err != nil {
			_ = rows.Close()
			return identity.ErrRegistryUnavailable
		}
		if _, exists := seen[tenant+"\x00"+principal]; !exists {
			_ = rows.Close()
			return identity.ErrRegistryInvalid
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return identity.ErrRegistryUnavailable
	}
	if err := rows.Close(); err != nil {
		return identity.ErrRegistryUnavailable
	}
	var mismatched uint64
	if err := tx.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM restore_epoch_floors WHERE recovery_reference != ?", manifestReference).Scan(&mismatched); err != nil || mismatched != 0 {
		return identity.ErrRegistryInvalid
	}
	if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET wall_high_water_ms = max(wall_high_water_ms, ?) WHERE singleton = 1 AND fence_state = 'restore_fenced'", highWaterMS); err != nil {
		return identity.ErrRegistryUnavailable
	}
	return tx.commit(ctx)
}

// CompleteRestore is the sole identity admission transition. It proves that
// the complete staged set belongs to the accepted manifest and binds the audit
// ledger receipt that committed the canonical restore_fence record.
func (r *Registry) CompleteRestore(ctx context.Context, databaseID, manifestReference, auditReceipt string) error {
	if !validUUID(databaseID) || !referenceText.MatchString(manifestReference) || !referenceText.MatchString(auditReceipt) {
		return identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	var actualID, fence string
	var existing sql.NullString
	if err := tx.conn.QueryRowContext(ctx, "SELECT database_id, fence_state, fence_receipt FROM identity_metadata WHERE singleton = 1").Scan(&actualID, &fence, &existing); err != nil || actualID != databaseID {
		return identity.ErrRegistryUnavailable
	}
	if fence == "admitted" && existing.Valid && existing.String == auditReceipt {
		return tx.commit(ctx)
	}
	if fence != "restore_fenced" {
		return identity.ErrRegistryFenced
	}
	var missing, mismatched uint64
	if err := tx.conn.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM principal_epochs p WHERE NOT EXISTS (SELECT 1 FROM restore_epoch_floors f WHERE f.tenant_id = p.tenant_id AND f.principal_id = p.principal_id)),
		(SELECT COUNT(*) FROM restore_epoch_floors WHERE recovery_reference != ?)`, manifestReference).Scan(&missing, &mismatched); err != nil || missing != 0 || mismatched != 0 {
		return identity.ErrRegistryInvalid
	}
	if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET fence_state = 'admitted', fence_receipt = ? WHERE singleton = 1 AND fence_state = 'restore_fenced'", auditReceipt); err != nil {
		return identity.ErrRegistryUnavailable
	}
	return tx.commit(ctx)
}

// RecoverClock clears a persisted clock fence only when an accountable caller
// supplies a wall value no earlier than the stored high-water and a receipt.
func (r *Registry) RecoverClock(ctx context.Context, recoveredAt time.Time, receipt string) error {
	recoveredMS, ok := unixMillis(recoveredAt)
	if !ok || recoveredAt.Nanosecond()%int(time.Millisecond) != 0 || !referenceText.MatchString(receipt) {
		return identity.ErrRegistryInvalid
	}
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return err
	}
	defer tx.rollback()
	var high int64
	var fence string
	if err := tx.conn.QueryRowContext(ctx, "SELECT wall_high_water_ms, fence_state FROM identity_metadata WHERE singleton = 1").Scan(&high, &fence); err != nil {
		return identity.ErrRegistryUnavailable
	}
	if fence != "clock_fenced" || recoveredMS < high {
		return identity.ErrRegistryFenced
	}
	if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET wall_high_water_ms = ?, fence_state = 'admitted', fence_receipt = ? WHERE singleton = 1 AND fence_state = 'clock_fenced'", recoveredMS, receipt); err != nil {
		return identity.ErrRegistryUnavailable
	}
	return tx.commit(ctx)
}

func (r *Registry) CleanupProofs(ctx context.Context) (int64, error) {
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return 0, err
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		return 0, finishClockFailure(ctx, tx, clockErr)
	}
	result, err := tx.conn.ExecContext(ctx, `DELETE FROM proof_replays WHERE rowid IN
		(SELECT rowid FROM proof_replays WHERE retain_until_ms < ? ORDER BY retain_until_ms LIMIT ?)`, nowMS, cleanupBatch)
	if err != nil {
		return 0, identity.ErrRegistryUnavailable
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, identity.ErrRegistryUnavailable
	}
	if err := tx.commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

func (r *Registry) expiryLoop() {
	defer close(r.closed)
	var timer *time.Timer
	var timerSignal <-chan time.Time
	reset := func() {
		if timer != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		delay, exists := r.nextExpiryDelay(context.Background())
		if !exists {
			timerSignal = nil
			return
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		timerSignal = timer.C
	}
	reset()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-timerSignal:
			r.expireDue(context.Background())
			reset()
		case <-r.wakeExpiry:
			reset()
		case <-r.stopExpiry:
			return
		}
	}
}

func (r *Registry) nextExpiryDelay(ctx context.Context) (time.Duration, bool) {
	var expiry sql.NullInt64
	if err := r.db.QueryRowContext(ctx, "SELECT MIN(expires_at_ms) FROM sessions WHERE state = 'active'").Scan(&expiry); err != nil {
		return time.Second, true
	}
	if !expiry.Valid {
		return 0, false
	}
	nowMS, ok := unixMillis(r.now())
	if !ok {
		return time.Second, true
	}
	if expiry.Int64 <= nowMS {
		return 0, true
	}
	deltaMS := expiry.Int64 - nowMS
	maxDelayMS := int64((24 * time.Hour) / time.Millisecond)
	if deltaMS > maxDelayMS {
		deltaMS = maxDelayMS
	}
	return time.Duration(deltaMS) * time.Millisecond, true
}

func (r *Registry) expireDue(ctx context.Context) {
	tx, err := beginImmediate(ctx, r.db)
	if err != nil {
		return
	}
	defer tx.rollback()
	nowMS, clockErr := r.observeClock(ctx, tx)
	if clockErr != nil {
		_ = finishClockFailure(ctx, tx, clockErr)
		return
	}
	rows, err := tx.conn.QueryContext(ctx, `SELECT tenant_id, participant_instance_id, session_epoch FROM sessions
		WHERE state = 'active' AND expires_at_ms <= ? ORDER BY expires_at_ms LIMIT ?`, nowMS, cleanupBatch)
	if err != nil {
		return
	}
	var keys []identity.SessionKey
	for rows.Next() {
		var key identity.SessionKey
		if err := rows.Scan(&key.TenantID, &key.ParticipantInstanceID, &key.SessionEpoch); err != nil {
			_ = rows.Close()
			return
		}
		keys = append(keys, key)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return
	}
	if len(keys) == 0 {
		_ = tx.commit(ctx)
		return
	}
	for _, key := range keys {
		if _, err := tx.conn.ExecContext(ctx, `UPDATE sessions SET state = 'expired'
			WHERE tenant_id = ? AND participant_instance_id = ? AND session_epoch = ? AND state = 'active' AND expires_at_ms <= ?`,
			key.TenantID, key.ParticipantInstanceID, key.SessionEpoch, nowMS); err != nil {
			return
		}
	}
	if err := tx.commit(ctx); err != nil {
		return
	}
	for _, key := range keys {
		r.notifyInactive(key)
	}
}

func (r *Registry) wakeScheduler() {
	select {
	case r.wakeExpiry <- struct{}{}:
	default:
	}
}

func (r *Registry) notifyInactive(key identity.SessionKey) {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.closeWatchersLocked(key)
}

func (r *Registry) closeWatchersLocked(key identity.SessionKey) {
	for signal := range r.watchers[key] {
		close(signal)
	}
	delete(r.watchers, key)
}

func (r *Registry) removeWatcher(key identity.SessionKey, signal chan struct{}) {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	delete(r.watchers[key], signal)
	if len(r.watchers[key]) == 0 {
		delete(r.watchers, key)
	}
}

func (r *Registry) observeClock(ctx context.Context, tx *immediateTx) (int64, error) {
	nowMS, ok := unixMillis(r.now())
	if !ok {
		return 0, identity.ErrRegistryUnavailable
	}
	var high int64
	var fence string
	if err := tx.conn.QueryRowContext(ctx, "SELECT wall_high_water_ms, fence_state FROM identity_metadata WHERE singleton = 1").Scan(&high, &fence); err != nil {
		return 0, identity.ErrRegistryUnavailable
	}
	if fence != "admitted" {
		return 0, identity.ErrRegistryFenced
	}
	if nowMS < high-clockTolerance.Milliseconds() {
		if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET fence_state = 'clock_fenced' WHERE singleton = 1"); err != nil {
			return 0, identity.ErrRegistryUnavailable
		}
		return 0, identity.ErrClockRollback
	}
	if nowMS > high {
		if _, err := tx.conn.ExecContext(ctx, "UPDATE identity_metadata SET wall_high_water_ms = ? WHERE singleton = 1", nowMS); err != nil {
			return 0, identity.ErrRegistryUnavailable
		}
		return nowMS, nil
	}
	return high, nil
}

func finishClockFailure(ctx context.Context, tx *immediateTx, err error) error {
	if errors.Is(err, identity.ErrClockRollback) {
		if commitErr := tx.commit(ctx); commitErr != nil {
			return commitErr
		}
	}
	return err
}

func reserveProof(ctx context.Context, tx *immediateTx, thumbprint [sha256.Size]byte, jti string, purpose identity.ProofPurpose, issuedAt time.Time, participant string) error {
	if !validProof(jti, issuedAt) || thumbprint == ([sha256.Size]byte{}) || (purpose != identity.ProofBootstrap && purpose != identity.ProofAuthentication) {
		return identity.ErrRegistryInvalid
	}
	retainUntil := issuedAt.UTC().Add(proofPastWindow + time.Millisecond)
	result, err := tx.conn.ExecContext(ctx, `INSERT INTO proof_replays
		(jwk_thumbprint, proof_jti, purpose, issued_at_ms, retain_until_ms, participant_instance_id)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, thumbprint[:], jti, purpose, issuedAt.UnixMilli(), retainUntil.UnixMilli(), participant)
	if err != nil {
		return identity.ErrRegistryUnavailable
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return identity.ErrProofReplay
	}
	return nil
}

func allocateEpoch(ctx context.Context, tx *immediateTx, tenant, principal string) (uint64, error) {
	var current, floor uint64
	if err := tx.conn.QueryRowContext(ctx, "SELECT last_epoch FROM principal_epochs WHERE tenant_id = ? AND principal_id = ?", tenant, principal).Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, identity.ErrRegistryUnavailable
	}
	if err := tx.conn.QueryRowContext(ctx, "SELECT epoch_floor FROM restore_epoch_floors WHERE tenant_id = ? AND principal_id = ?", tenant, principal).Scan(&floor); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, identity.ErrRegistryUnavailable
	}
	if floor > current {
		current = floor
	}
	if current >= maxJSONSafeInt {
		return 0, identity.ErrEpochExhausted
	}
	next := current + 1
	if _, err := tx.conn.ExecContext(ctx, `INSERT INTO principal_epochs (tenant_id, principal_id, last_epoch) VALUES (?, ?, ?)
		ON CONFLICT (tenant_id, principal_id) DO UPDATE SET last_epoch = excluded.last_epoch`, tenant, principal, next); err != nil {
		return 0, identity.ErrRegistryUnavailable
	}
	return next, nil
}

func activeByOperation(ctx context.Context, query *sql.Conn, operationID string) (identity.ActiveSession, error) {
	var result identity.ActiveSession
	var thumb []byte
	var expiry int64
	if err := query.QueryRowContext(ctx, `SELECT tenant_id, principal_id, participant_instance_id, session_epoch, dpop_thumbprint, expires_at_ms
		FROM sessions WHERE bootstrap_operation_id = ? AND state = 'active'`, operationID).Scan(&result.TenantID, &result.PrincipalID, &result.ParticipantInstanceID, &result.SessionEpoch, &thumb, &expiry); err != nil || len(thumb) != sha256.Size {
		return identity.ActiveSession{}, identity.ErrRegistryUnavailable
	}
	copy(result.DPoPThumbprint[:], thumb)
	result.ExpiresAt = time.UnixMilli(expiry).UTC()
	return result, nil
}

func validateBootstrap(request identity.BootstrapReservation) error {
	s := request.Session
	if !validTenant(s.TenantID) || !validDigestText(s.PrincipalID) || !validUUIDv7(s.ParticipantInstanceID) || s.SessionEpoch != 0 || s.TokenDigest == ([sha256.Size]byte{}) || s.DPoPThumbprint == ([sha256.Size]byte{}) || !validUUIDv7(s.BootstrapOperationID) || !validTime(s.IssuedAt) || !validTime(s.ExpiresAt) || !s.ExpiresAt.After(s.IssuedAt) || !validProof(request.ProofJTI, request.ProofIAT) {
		return identity.ErrRegistryInvalid
	}
	return nil
}

func validSessionKey(key identity.SessionKey) bool {
	return validTenant(key.TenantID) && validUUIDv7(key.ParticipantInstanceID) && key.SessionEpoch > 0 && key.SessionEpoch <= maxJSONSafeInt
}

func validProof(jti string, issuedAt time.Time) bool {
	return len(jti) >= 16 && len(jti) <= 128 && base64URL(jti) && validTime(issuedAt)
}

func validTenant(value string) bool { return tenantPattern.MatchString(value) }

func validDigestText(value string) bool { return len(value) == 43 && base64URL(value) }

func base64URL(value string) bool {
	for index := range len(value) {
		c := value[index]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func validUUIDv7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.Version() == 7 && parsed.String() == value
}

func validTime(value time.Time) bool {
	_, ok := unixMillis(value)
	return ok && value.Nanosecond()%int(time.Millisecond) == 0
}

func unixMillis(value time.Time) (int64, bool) {
	if value.Location() == nil {
		return 0, false
	}
	milliseconds := value.UTC().UnixMilli()
	return milliseconds, milliseconds >= 0 && uint64(milliseconds) <= maxJSONSafeInt
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return identity.ErrRegistryInvalid
	}
	return ctx.Err()
}

func hasSessionCollision(ctx context.Context, query *sql.Conn, session identity.PendingSession) (bool, error) {
	var found int
	err := query.QueryRowContext(ctx, `SELECT 1 FROM sessions WHERE participant_instance_id = ? OR token_digest = ? OR bootstrap_operation_id = ? LIMIT 1`, session.ParticipantInstanceID, session.TokenDigest[:], session.BootstrapOperationID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, identity.ErrRegistryUnavailable
	}
	return true, nil
}

type immediateTx struct {
	conn      *sql.Conn
	committed bool
}

func beginImmediate(ctx context.Context, db *sql.DB) (*immediateTx, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, identity.ErrRegistryUnavailable
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, identity.ErrRegistryUnavailable
	}
	return &immediateTx{conn: conn}, nil
}

func (tx *immediateTx) commit(ctx context.Context) error {
	if _, err := tx.conn.ExecContext(ctx, "COMMIT"); err != nil {
		_ = tx.conn.Close()
		return identity.ErrRegistryUnavailable
	}
	tx.committed = true
	if err := tx.conn.Close(); err != nil {
		return identity.ErrRegistryUnavailable
	}
	return nil
}

func (tx *immediateTx) rollback() {
	if tx == nil || tx.conn == nil || tx.committed {
		return
	}
	_, _ = tx.conn.ExecContext(context.Background(), "ROLLBACK")
	_ = tx.conn.Close()
}
