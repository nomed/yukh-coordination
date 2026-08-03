package localcustody

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/clientauth"
)

type fixedRoot struct {
	key [32]byte
	err error
}

func (r fixedRoot) RootKey(context.Context, string) ([32]byte, error) {
	if r.err != nil {
		return [32]byte{}, r.err
	}
	return r.key, nil
}

func TestEncryptedStoreSignerAndExactCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.db")
	store := openStore(t, path)
	defer store.Close()

	provisioned, err := store.ProvisionP256(context.Background(), "profile-a")
	if err != nil || !provisioned.Created() {
		t.Fatalf("provision: created=%v err=%v", provisioned.Created(), err)
	}
	signer := provisioned.Signer()
	jwk, err := signer.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord(t, signer.KeyReference(), jwk.Thumbprint(), "secret-token-a")
	revision1, err := store.Save(context.Background(), "profile-a", clientauth.AbsentRevision(), record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), "profile-a", clientauth.AbsentRevision(), record); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("duplicate create: %v", err)
	}
	loaded, err := store.Load(context.Background(), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	loadedRecord, err := loaded.Record()
	if err != nil || loadedRecord.Credential() != record.Credential() || loadedRecord.ProofKeyReference() != signer.KeyReference() {
		t.Fatalf("loaded record mismatch: %v", err)
	}
	revision2, err := store.Save(context.Background(), "profile-a", revision1, record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), "profile-a", revision1); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := store.Delete(context.Background(), "profile-a", revision2); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(context.Background(), signer.KeyReference()); !errors.Is(err, clientauth.ErrProofSigner) {
		t.Fatalf("committed signer retired: %v", err)
	}

	input := []byte("header.payload")
	signature, err := signer.SignES256(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	x, y := jwk.Coordinates()
	public := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x[:]), Y: new(big.Int).SetBytes(y[:])}
	digest := sha256.Sum256(input)
	if !ecdsa.Verify(&public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("signature did not verify")
	}

	assertNoPlaintext(t, path, record.Credential())
}

func TestConcurrentAbsentCreateHasOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.db")
	first := openStore(t, path)
	defer first.Close()
	second := openStore(t, path)
	defer second.Close()
	provisioned, err := first.ProvisionP256(context.Background(), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := provisioned.Signer().PublicJWK()
	record := testRecord(t, provisioned.Signer().KeyReference(), jwk.Thumbprint(), "secret-token-b")

	stores := []*Store{first, second}
	var wg sync.WaitGroup
	errorsOut := make(chan error, len(stores))
	for _, store := range stores {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			_, saveErr := store.Save(context.Background(), "profile-a", clientauth.AbsentRevision(), record)
			errorsOut <- saveErr
		}(store)
	}
	wg.Wait()
	close(errorsOut)
	var successes, conflicts int
	for err := range errorsOut {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, clientauth.ErrCredentialConflict):
			conflicts++
		default:
			t.Fatalf("unexpected outcome: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflict=%d", successes, conflicts)
	}
}

func TestTamperWrongRootAndProvisionalRetirementFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody.db")
	store := openStore(t, path)
	provisioned, err := store.ProvisionP256(context.Background(), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(context.Background(), provisioned.Signer().KeyReference()); err != nil {
		t.Fatalf("retire provisional: %v", err)
	}
	if _, err := store.Open(context.Background(), provisioned.Signer().KeyReference()); !errors.Is(err, clientauth.ErrProofKeyMissing) {
		t.Fatalf("retired signer: %v", err)
	}

	provisioned, err = store.ProvisionP256(context.Background(), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	jwk, _ := provisioned.Signer().PublicJWK()
	record := testRecord(t, provisioned.Signer().KeyReference(), jwk.Thumbprint(), "secret-token-c")
	if _, err := store.Save(context.Background(), "profile-a", clientauth.AbsentRevision(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("UPDATE sessions SET ciphertext = randomblob(length(ciphertext)) WHERE profile = 'profile-a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background(), "profile-a"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tamper: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	wrong := fixedRoot{key: [32]byte{9, 8, 7}}
	reopened, err := Open(path, wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Open(context.Background(), provisioned.Signer().KeyReference()); !errors.Is(err, clientauth.ErrProofSigner) {
		t.Fatalf("wrong root: %v", err)
	}
}

func TestConfigurationRootErrorsAndEncryptionLimitAreClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "permissive.db"), fixedRoot{key: [32]byte{1}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("permissive directory: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open("relative.db", fixedRoot{key: [32]byte{1}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("relative path: %v", err)
	}
	store, err := Open(filepath.Join(dir, "custody.db"), fixedRoot{err: errors.New("provider /secret/path")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.ProvisionP256(context.Background(), "profile-a"); !errors.Is(err, clientauth.ErrProofSigner) || strings.Contains(err.Error(), "provider") {
		t.Fatalf("root error: %v", err)
	}
	if _, err := store.db.Exec("UPDATE custody_meta SET encryptions = ? WHERE id = 1", maximumEncryptions); err != nil {
		t.Fatal(err)
	}
	store.root = fixedRoot{key: [32]byte{1, 2, 3}}
	if _, err := store.ProvisionP256(context.Background(), "profile-a"); !errors.Is(err, clientauth.ErrProofSigner) {
		t.Fatalf("limit: %v", err)
	}
}

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	root := fixedRoot{key: [32]byte{1, 2, 3, 4, 5}}
	store, err := Open(path, root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testRecord(t *testing.T, reference string, thumbprint [32]byte, marker string) *clientauth.SessionRecord {
	t.Helper()
	participant, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes := sha256.Sum256([]byte(marker))
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, err := clientauth.NewSessionRecord(participant.String(), 1, base64.RawURLEncoding.EncodeToString(tokenBytes[:]), now, now.Add(time.Minute), reference, thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func assertNoPlaintext(t *testing.T, path, secret string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		raw, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("plaintext found in %s", filepath.Base(candidate))
		}
	}
}
