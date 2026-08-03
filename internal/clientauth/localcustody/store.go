// Package localcustody implements the environment-neutral RFC-0018 encrypted
// SQLite custody foundation. Secret Service and other root-key providers live
// behind RootKeySource and are not dependencies of this package.
package localcustody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/clientauth"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	_ "modernc.org/sqlite"
)

const (
	schemaVersion        = 1
	maximumEncryptions   = uint64(1 << 32)
	maximumPlaintext     = 16 * 1024
	maximumSigningInput  = 32 * 1024
	databaseBusyTimeout  = 5 * time.Second
	revisionRandomBytes  = 16
	keyReferencePrefix   = "local-p256:"
)

var (
	ErrInvalidConfiguration = errors.New("local custody: invalid configuration")
	ErrRootKeyUnavailable   = errors.New("local custody: root key unavailable")
	ErrCorrupt              = errors.New("local custody: corrupt encrypted state")
	ErrEncryptionLimit      = errors.New("local custody: encryption limit reached")
)

// RootKeySource returns the exact 32-byte root key for one opaque profile.
// Implementations must be explicitly constructed; Store performs no provider
// discovery and reads no environment variables.
type RootKeySource interface {
	RootKey(context.Context, string) ([32]byte, error)
}

type Store struct {
	db      *sql.DB
	root    RootKeySource
	entropy io.Reader
	path    string
}

var (
	_ clientauth.CredentialStore  = (*Store)(nil)
	_ clientauth.ProofSignerStore = (*Store)(nil)
)

// Open creates or opens the encrypted local-custody database. The parent
// directory must already be private and owned by the effective user.
func Open(path string, root RootKeySource) (*Store, error) {
	return open(path, root, rand.Reader)
}

func open(path string, root RootKeySource, entropy io.Reader) (*Store, error) {
	if root == nil || entropy == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInvalidConfiguration
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(info) {
		return nil, ErrInvalidConfiguration
	}
	created := false
	if existing, statErr := os.Lstat(path); statErr == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 || existing.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(existing) {
			return nil, ErrInvalidConfiguration
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, clientauth.ErrCredentialStore
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, clientauth.ErrCredentialStore
		}
		created = true
	} else {
		return nil, ErrInvalidConfiguration
	}

	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "_busy_timeout=5000&_foreign_keys=on&_journal_mode=wal&_synchronous=full"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, clientauth.ErrCredentialStore
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, root: root, entropy: entropy, path: path}
	if err := store.initialize(context.Background()); err != nil {
		_ = db.Close()
		if created {
			_ = os.Remove(path)
		}
		return nil, err
	}
	if err := store.validateFiles(); err != nil {
		_ = db.Close()
		return nil, clientauth.ErrCredentialStore
	}
	return store, nil
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func (s *Store) initialize(ctx context.Context) error {
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		fmt.Sprintf("PRAGMA busy_timeout=%d", databaseBusyTimeout.Milliseconds()),
		`CREATE TABLE IF NOT EXISTS custody_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			schema_version INTEGER NOT NULL CHECK (schema_version = 1),
			encryptions INTEGER NOT NULL CHECK (encryptions >= 0)
		) STRICT`,
		`INSERT OR IGNORE INTO custody_meta (id, schema_version, encryptions) VALUES (1, 1, 0)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			profile TEXT PRIMARY KEY,
			revision TEXT NOT NULL UNIQUE,
			proof_reference TEXT NOT NULL,
			nonce BLOB NOT NULL CHECK (length(nonce) = 24),
			ciphertext BLOB NOT NULL CHECK (length(ciphertext) > 16)
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS signers (
			reference TEXT PRIMARY KEY,
			profile TEXT NOT NULL UNIQUE,
			provisional INTEGER NOT NULL CHECK (provisional IN (0, 1)),
			nonce BLOB NOT NULL CHECK (length(nonce) = 24),
			ciphertext BLOB NOT NULL CHECK (length(ciphertext) > 16)
		) STRICT`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return clientauth.ErrCredentialStore
		}
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT schema_version FROM custody_meta WHERE id = 1").Scan(&version); err != nil || version != schemaVersion {
		return ErrCorrupt
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return clientauth.ErrCredentialStore
	}
	return s.db.Close()
}

func (s *Store) validateFiles() error {
	for _, path := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(info) {
			return ErrInvalidConfiguration
		}
	}
	return nil
}

type sessionPlaintext struct {
	SpecVersion           string `json:"spec_version"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	SessionEpoch          uint64 `json:"session_epoch"`
	SessionToken          string `json:"session_token"`
	IssuedAt              string `json:"issued_at"`
	ExpiresAt             string `json:"expires_at"`
	ProofKeyReference     string `json:"proof_key_reference"`
	ProofJWKThumbprint    string `json:"proof_jwk_thumbprint"`
}

func (s *Store) Load(ctx context.Context, profile string) (clientauth.StoredSession, error) {
	if s == nil || s.db == nil || invalidProfile(profile) || ctx.Err() != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialStore
	}
	var revision, proofReference string
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT revision, proof_reference, nonce, ciphertext FROM sessions WHERE profile = ?", profile).Scan(&revision, &proofReference, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return clientauth.StoredSession{}, clientauth.ErrCredentialMissing
	}
	if err != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialStore
	}
	root, err := s.loadRoot(ctx, profile)
	if err != nil {
		return clientauth.StoredSession{}, err
	}
	plaintext, err := openEnvelope(root, profile, "session", profile, revision, proofReference, nonce, ciphertext)
	clear(root[:])
	if err != nil {
		return clientauth.StoredSession{}, ErrCorrupt
	}
	record, err := decodeSession(plaintext)
	clear(plaintext)
	if err != nil || record.ProofKeyReference() != proofReference {
		return clientauth.StoredSession{}, ErrCorrupt
	}
	rev, err := clientauth.NewRevision(revision)
	if err != nil {
		return clientauth.StoredSession{}, ErrCorrupt
	}
	stored, err := clientauth.NewStoredSession(record, rev)
	if err != nil {
		return clientauth.StoredSession{}, ErrCorrupt
	}
	return stored, nil
}

func (s *Store) Save(ctx context.Context, profile string, expected clientauth.Revision, record *clientauth.SessionRecord) (clientauth.Revision, error) {
	if s == nil || s.db == nil || invalidProfile(profile) || record == nil || ctx.Err() != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	expectedValue, expectedPresent := expected.ProviderValue()
	if !expectedPresent && !expected.IsAbsent() {
		return clientauth.Revision{}, clientauth.ErrCredentialConflict
	}
	plaintext, err := encodeSession(record)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	defer clear(plaintext)
	revisionBytes := make([]byte, revisionRandomBytes)
	if _, err := io.ReadFull(s.entropy, revisionBytes); err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	revision := base64.RawURLEncoding.EncodeToString(revisionBytes)
	clear(revisionBytes)
	root, err := s.loadRoot(ctx, profile)
	if err != nil {
		return clientauth.Revision{}, err
	}
	nonce, ciphertext, err := sealEnvelope(s.entropy, root, profile, "session", profile, revision, record.ProofKeyReference(), plaintext)
	clear(root[:])
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	defer tx.Rollback()
	if err := consumeEncryption(ctx, tx); err != nil {
		return clientauth.Revision{}, err
	}
	var result sql.Result
	if expectedPresent {
		result, err = tx.ExecContext(ctx, "UPDATE sessions SET revision = ?, proof_reference = ?, nonce = ?, ciphertext = ? WHERE profile = ? AND revision = ?", revision, record.ProofKeyReference(), nonce, ciphertext, profile, expectedValue)
	} else {
		result, err = tx.ExecContext(ctx, "INSERT INTO sessions (profile, revision, proof_reference, nonce, ciphertext) VALUES (?, ?, ?, ?, ?)", profile, revision, record.ProofKeyReference(), nonce, ciphertext)
	}
	if err != nil {
		if constraint(err) {
			return clientauth.Revision{}, clientauth.ErrCredentialConflict
		}
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return clientauth.Revision{}, clientauth.ErrCredentialConflict
	}
	if result, err = tx.ExecContext(ctx, "UPDATE signers SET provisional = 0 WHERE profile = ? AND reference = ?", profile, record.ProofKeyReference()); err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	rows, err = result.RowsAffected()
	if err != nil || rows != 1 {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	if err := tx.Commit(); err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	return clientauth.NewRevision(revision)
}

func (s *Store) Delete(ctx context.Context, profile string, expected clientauth.Revision) error {
	value, present := expected.ProviderValue()
	if s == nil || s.db == nil || invalidProfile(profile) || !present || ctx.Err() != nil {
		return clientauth.ErrCredentialConflict
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE profile = ? AND revision = ?", profile, value)
	if err != nil {
		return clientauth.ErrCredentialStore
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return clientauth.ErrCredentialConflict
	}
	return nil
}

func (s *Store) ProvisionP256(ctx context.Context, profile string) (clientauth.ProvisionedSigner, error) {
	if s == nil || s.db == nil || invalidProfile(profile) || ctx.Err() != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	var existing string
	err := s.db.QueryRowContext(ctx, "SELECT reference FROM signers WHERE profile = ?", profile).Scan(&existing)
	if err == nil {
		signer, openErr := s.Open(ctx, existing)
		if openErr != nil {
			return clientauth.ProvisionedSigner{}, openErr
		}
		return clientauth.NewProvisionedSigner(signer, false)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), s.entropy)
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || len(der) > maximumPlaintext {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	defer clear(der)
	id, err := uuid.NewV7FromReader(s.entropy)
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	reference := keyReferencePrefix + id.String()
	root, err := s.loadRoot(ctx, profile)
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	nonce, ciphertext, err := sealEnvelope(s.entropy, root, profile, "signer", reference, "", "", der)
	clear(root[:])
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	defer tx.Rollback()
	if err := consumeEncryption(ctx, tx); err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO signers (reference, profile, provisional, nonce, ciphertext) VALUES (?, ?, 1, ?, ?)", reference, profile, nonce, ciphertext)
	if err != nil {
		if constraint(err) {
			if queryErr := tx.QueryRowContext(ctx, "SELECT reference FROM signers WHERE profile = ?", profile).Scan(&existing); queryErr != nil {
				return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
			}
			_ = tx.Rollback()
			signer, openErr := s.Open(ctx, existing)
			if openErr != nil {
				return clientauth.ProvisionedSigner{}, openErr
			}
			return clientauth.NewProvisionedSigner(signer, false)
		}
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	if err := tx.Commit(); err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	signer, err := softwareSigner(reference, key)
	if err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	return clientauth.NewProvisionedSigner(signer, true)
}

func (s *Store) Open(ctx context.Context, reference string) (clientauth.ProofSigner, error) {
	if s == nil || s.db == nil || !validReference(reference) || ctx.Err() != nil {
		return nil, clientauth.ErrProofSigner
	}
	var profile string
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, "SELECT profile, nonce, ciphertext FROM signers WHERE reference = ?", reference).Scan(&profile, &nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, clientauth.ErrProofKeyMissing
	}
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	root, err := s.loadRoot(ctx, profile)
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	der, err := openEnvelope(root, profile, "signer", reference, "", "", nonce, ciphertext)
	clear(root[:])
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	defer clear(der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D == nil || key.D.Sign() <= 0 || key.D.Cmp(key.Params().N) >= 0 {
		return nil, clientauth.ErrProofSigner
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || len(canonical) != len(der) || subtle.ConstantTimeCompare(canonical, der) != 1 {
		clear(canonical)
		return nil, clientauth.ErrProofSigner
	}
	clear(canonical)
	return softwareSigner(reference, key)
}

func (s *Store) Retire(ctx context.Context, reference string) error {
	if s == nil || s.db == nil || !validReference(reference) || ctx.Err() != nil {
		return clientauth.ErrProofSigner
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM signers
		WHERE reference = ? AND provisional = 1
		AND NOT EXISTS (SELECT 1 FROM sessions WHERE proof_reference = ?)`, reference, reference)
	if err != nil {
		return clientauth.ErrProofSigner
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return clientauth.ErrProofSigner
	}
	return nil
}

type signer struct {
	reference string
	key       *ecdsa.PrivateKey
	jwk       clientauth.PublicP256JWK
}

func softwareSigner(reference string, key *ecdsa.PrivateKey) (*signer, error) {
	if key == nil || key.X == nil || key.Y == nil {
		return nil, clientauth.ErrProofSigner
	}
	jwk, err := clientauth.NewPublicP256JWK(key.X.FillBytes(make([]byte, 32)), key.Y.FillBytes(make([]byte, 32)))
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	return &signer{reference: reference, key: key, jwk: jwk}, nil
}

func (s *signer) KeyReference() string { return s.reference }
func (s *signer) PublicJWK() (clientauth.PublicP256JWK, error) {
	if s == nil || s.key == nil {
		return clientauth.PublicP256JWK{}, clientauth.ErrProofSigner
	}
	return s.jwk, nil
}
func (s *signer) SignES256(ctx context.Context, input []byte) ([64]byte, error) {
	var signature [64]byte
	if s == nil || s.key == nil || len(input) == 0 || len(input) > maximumSigningInput || ctx.Err() != nil {
		return signature, clientauth.ErrProofSigner
	}
	digest := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil || !ecdsa.Verify(&s.key.PublicKey, digest[:], r, ss) {
		return signature, clientauth.ErrProofSigner
	}
	r.FillBytes(signature[:32])
	ss.FillBytes(signature[32:])
	return signature, nil
}

func (s *Store) loadRoot(ctx context.Context, profile string) ([32]byte, error) {
	if s.root == nil {
		return [32]byte{}, ErrRootKeyUnavailable
	}
	key, err := s.root.RootKey(ctx, profile)
	if err != nil || zero(key[:]) {
		clear(key[:])
		return [32]byte{}, ErrRootKeyUnavailable
	}
	return key, nil
}

func sealEnvelope(entropy io.Reader, root [32]byte, profile, domain, object, revision, proofReference string, plaintext []byte) ([]byte, []byte, error) {
	if len(plaintext) == 0 || len(plaintext) > maximumPlaintext {
		return nil, nil, ErrCorrupt
	}
	key, err := deriveKey(root, profile, domain)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return nil, nil, err
	}
	aad := associatedData(profile, domain, object, revision, proofReference)
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func openEnvelope(root [32]byte, profile, domain, object, revision, proofReference string, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX || len(ciphertext) <= chacha20poly1305.Overhead || len(ciphertext) > maximumPlaintext+chacha20poly1305.Overhead {
		return nil, ErrCorrupt
	}
	key, err := deriveKey(root, profile, domain)
	if err != nil {
		return nil, ErrCorrupt
	}
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrCorrupt
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData(profile, domain, object, revision, proofReference))
	if err != nil || len(plaintext) == 0 || len(plaintext) > maximumPlaintext {
		clear(plaintext)
		return nil, ErrCorrupt
	}
	return plaintext, nil
}

func deriveKey(root [32]byte, profile, domain string) ([]byte, error) {
	salt := sha256.Sum256([]byte(fmt.Sprintf("yukh-local-custody:%d:%s", schemaVersion, profile)))
	reader := hkdf.New(sha256.New, root[:], salt[:], []byte("aead:"+domain))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

func associatedData(values ...string) []byte {
	var buffer bytes.Buffer
	_ = binary.Write(&buffer, binary.BigEndian, uint32(schemaVersion))
	for _, value := range values {
		_ = binary.Write(&buffer, binary.BigEndian, uint32(len(value)))
		buffer.WriteString(value)
	}
	return buffer.Bytes()
}

func consumeEncryption(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, "UPDATE custody_meta SET encryptions = encryptions + 1 WHERE id = 1 AND encryptions < ?", maximumEncryptions)
	if err != nil {
		return clientauth.ErrCredentialStore
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return clientauth.ErrCredentialStore
	}
	if rows != 1 {
		return ErrEncryptionLimit
	}
	return nil
}

func encodeSession(record *clientauth.SessionRecord) ([]byte, error) {
	if record == nil {
		return nil, clientauth.ErrInvalidCredential
	}
	thumbprint := record.ProofJWKThumbprint()
	value := sessionPlaintext{
		SpecVersion: record.SpecVersion(), ParticipantInstanceID: record.ParticipantInstanceID(),
		SessionEpoch: record.SessionEpoch(), SessionToken: record.Credential(),
		IssuedAt: record.IssuedAt().Format(time.RFC3339Nano), ExpiresAt: record.ExpiresAt().Format(time.RFC3339Nano),
		ProofKeyReference: record.ProofKeyReference(), ProofJWKThumbprint: base64.RawURLEncoding.EncodeToString(thumbprint[:]),
	}
	return json.Marshal(value)
}

func decodeSession(raw []byte) (*clientauth.SessionRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value sessionPlaintext
	if err := decoder.Decode(&value); err != nil || value.SpecVersion != "0.1" {
		return nil, ErrCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrCorrupt
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, value.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	thumbprint, thumbErr := base64.RawURLEncoding.Strict().DecodeString(value.ProofJWKThumbprint)
	if issuedErr != nil || expiresErr != nil || thumbErr != nil || len(thumbprint) != 32 {
		return nil, ErrCorrupt
	}
	var fixed [32]byte
	copy(fixed[:], thumbprint)
	return clientauth.NewSessionRecord(value.ParticipantInstanceID, value.SessionEpoch, value.SessionToken, issued.UTC(), expires.UTC(), value.ProofKeyReference, fixed)
}

func invalidProfile(profile string) bool {
	if profile == "" || len(profile) > 128 {
		return true
	}
	for _, r := range profile {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			return true
		}
	}
	return false
}

func validReference(reference string) bool {
	return strings.HasPrefix(reference, keyReferencePrefix) && len(reference) == len(keyReferencePrefix)+36
}

func constraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint")
}

func zero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
