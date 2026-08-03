package gcpworkload

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/clientauth"
)

type fixedOperationIDs struct{ next byte }

func (s *fixedOperationIDs) NewOperationID() ([16]byte, error) {
	s.next++
	var value [16]byte
	for index := range value {
		value[index] = s.next
	}
	return value, nil
}

type deterministicAEAD struct{ version KeyVersion }

func (a deterministicAEAD) Encrypt(_ context.Context, version KeyVersion, plaintext Plaintext, _ AssociatedData) (RawCiphertext, error) {
	value, _, ok := plaintext.ProviderValue()
	if !ok || version.value != a.version.value {
		return RawCiphertext{}, ErrInvalidContract
	}
	return NewRawCiphertext(version, []byte("0123456789ab"), standardTagBytes, append(value, make([]byte, standardTagBytes)...))
}

func (a deterministicAEAD) Decrypt(_ context.Context, version KeyVersion, ciphertext RawCiphertext, _ AssociatedData) (Plaintext, error) {
	value := ciphertext.Ciphertext()
	if version.value != a.version.value || len(value) <= standardTagBytes {
		return Plaintext{}, ErrIntegrity
	}
	return NewPlaintext(value[:len(value)-standardTagBytes])
}

type memoryObjectStore struct {
	body            []byte
	generation      uint64
	verifyErr       error
	ambiguousSave   bool
	ambiguousDelete bool
	deleteScript    []error
}

type wrongBindingStore struct{ *memoryObjectStore }

func (wrongBindingStore) Binding() (string, string, bool) {
	return "other-custody", "profiles/opaque", true
}

func (*memoryObjectStore) Binding() (string, string, bool) {
	return "yukh-custody", "profiles/opaque", true
}

func (s *memoryObjectStore) Load(context.Context) (StoredObject, error) {
	if len(s.body) == 0 {
		return StoredObject{}, ErrAbsent
	}
	generation, _ := NewGeneration(s.generation)
	return NewStoredObject(s.body, generation, Checksum(s.body))
}

func (s *memoryObjectStore) LoadGeneration(ctx context.Context, expected Generation) (StoredObject, error) {
	if s.verifyErr != nil {
		return StoredObject{}, s.verifyErr
	}
	loaded, err := s.Load(ctx)
	if err != nil {
		return StoredObject{}, err
	}
	if !sameGeneration(expected, loaded.Generation()) {
		return StoredObject{}, ErrConflict
	}
	return loaded, nil
}

func (s *memoryObjectStore) Save(_ context.Context, expected Generation, body []byte, checksum CRC32C) (Generation, error) {
	value, valid := expected.ProviderValue()
	if !valid || !checksum.Matches(body) || expected.IsAbsent() != (len(s.body) == 0) || (!expected.IsAbsent() && value != s.generation) {
		return Generation{}, ErrConflict
	}
	s.generation++
	if s.generation == 1 {
		s.generation = 41
	}
	s.body = clone(body)
	result, _ := NewGeneration(s.generation)
	if s.ambiguousSave {
		s.ambiguousSave = false
		return Generation{}, ErrAmbiguous
	}
	return result, nil
}

func (s *memoryObjectStore) Delete(_ context.Context, expected Generation) error {
	value, valid := expected.ProviderValue()
	if !valid || expected.IsAbsent() || len(s.body) == 0 || value != s.generation {
		return ErrConflict
	}
	if len(s.deleteScript) != 0 {
		result := s.deleteScript[0]
		s.deleteScript = s.deleteScript[1:]
		return result
	}
	s.body = nil
	if s.ambiguousDelete {
		s.ambiguousDelete = false
		return ErrAmbiguous
	}
	return nil
}

func TestCredentialStoreLifecycleAndLostResponses(t *testing.T) {
	store, object, record := credentialFixture(t)
	ctx := context.Background()

	object.ambiguousSave = true
	revision, err := store.Save(ctx, "server", clientauth.AbsentRevision(), record)
	if err != nil {
		t.Fatalf("resolve lost create response: %v", err)
	}
	loaded, err := store.Load(ctx, "server")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	loadedRecord, err := loaded.Record()
	if err != nil || !sameRecord(record, loadedRecord) {
		t.Fatal("loaded record differs from saved record")
	}
	if got, ok := revision.ProviderValue(); !ok || got != "41" {
		t.Fatalf("unexpected revision: %q %v", got, ok)
	}

	if _, err := store.Save(ctx, "server", clientauth.AbsentRevision(), record); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("stale create error = %v", err)
	}
	updated, err := clientauth.NewSessionRecord(record.ParticipantInstanceID(), 2, record.Credential(), record.IssuedAt(), record.ExpiresAt(), record.ProofKeyReference(), record.ProofJWKThumbprint())
	if err != nil {
		t.Fatal(err)
	}
	nextRevision, err := store.Save(ctx, "server", revision, updated)
	if err != nil {
		t.Fatalf("exact replacement: %v", err)
	}
	if _, err := store.Save(ctx, "server", revision, updated); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("stale replacement error = %v", err)
	}
	if err := store.Delete(ctx, "server", revision); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("stale delete error = %v", err)
	}
	object.ambiguousDelete = true
	if err := store.Delete(ctx, "server", nextRevision); err != nil {
		t.Fatalf("resolve lost delete response: %v", err)
	}
	if _, err := store.Load(ctx, "server"); !errors.Is(err, clientauth.ErrCredentialMissing) {
		t.Fatalf("load after delete error = %v", err)
	}
}

func TestCredentialStoreRejectsWrongProfileAndSigner(t *testing.T) {
	store, _, record := credentialFixture(t)
	if _, err := store.Save(context.Background(), "other", clientauth.AbsentRevision(), record); !errors.Is(err, clientauth.ErrInvalidCredential) {
		t.Fatalf("wrong profile error = %v", err)
	}
	wrong := *record
	thumbprint := wrong.ProofJWKThumbprint()
	thumbprint[0] ^= 0xff
	badRecord, err := clientauth.NewSessionRecord(wrong.ParticipantInstanceID(), wrong.SessionEpoch(), wrong.Credential(), wrong.IssuedAt(), wrong.ExpiresAt(), wrong.ProofKeyReference(), thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), "server", clientauth.AbsentRevision(), badRecord); !errors.Is(err, clientauth.ErrInvalidCredential) {
		t.Fatalf("wrong signer error = %v", err)
	}
}

func TestCredentialStoreRejectsObjectAADBindingMismatch(t *testing.T) {
	store, object, _ := credentialFixture(t)
	if _, err := NewCredentialStore(store.profile, wrongBindingStore{object}, store.aead, store.aad, &fixedOperationIDs{}); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("binding mismatch error = %v", err)
	}
}

func TestCredentialStoreClassifiesVerificationRaceAsConflict(t *testing.T) {
	store, object, record := credentialFixture(t)
	object.verifyErr = ErrConflict
	if _, err := store.Save(context.Background(), "server", clientauth.AbsentRevision(), record); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("verification race error = %v", err)
	}
}

func TestCredentialStoreAcceptsAbsentOnControlledDeleteRetry(t *testing.T) {
	store, object, record := credentialFixture(t)
	revision, err := store.Save(context.Background(), "server", clientauth.AbsentRevision(), record)
	if err != nil {
		t.Fatal(err)
	}
	object.deleteScript = []error{ErrAmbiguous, ErrAbsent}
	if err := store.Delete(context.Background(), "server", revision); err != nil {
		t.Fatalf("controlled delete retry: %v", err)
	}
}

func credentialFixture(t *testing.T) (*CredentialStore, *memoryObjectStore, *clientauth.SessionRecord) {
	t.Helper()
	encryption, err := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/session/cryptoKeyVersions/1")
	if err != nil {
		t.Fatal(err)
	}
	signing, err := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/proof/cryptoKeyVersions/2")
	if err != nil {
		t.Fatal(err)
	}
	profileDigest := sha256Digest(profileDigestDomain + "server")
	thumbprint := sha256Digest("signer")
	aad, err := NewAssociatedData(profileDigest, "yukh-custody", "profiles/opaque", encryption, signing, thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	object := &memoryObjectStore{}
	store, err := NewCredentialStore("server", object, deterministicAEAD{version: encryption}, aad, &fixedOperationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	participant, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	for index := range token {
		token[index] = byte(index + 1)
	}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	record, err := clientauth.NewSessionRecord(participant.String(), 1, base64.RawURLEncoding.EncodeToString(token[:]), now, now.Add(time.Minute), signing.value, thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	return store, object, record
}

func sha256Digest(value string) [32]byte { return sha256.Sum256([]byte(value)) }
