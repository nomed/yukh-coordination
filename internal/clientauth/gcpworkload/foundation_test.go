package gcpworkload

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

const encryptionResource = "projects/123456789012/locations/europe-west8/keyRings/yukh-custody/cryptoKeys/session-records/cryptoKeyVersions/7"
const signingResource = "projects/123456789012/locations/europe-west8/keyRings/yukh-custody/cryptoKeys/dpop-signer/cryptoKeyVersions/3"
const aadGoldenSHA256 = "e3e4e6301fd0d5c45473d22c68c629ae06bee99113f200a0bd2f8af5f0d55cc4"
const envelopeGoldenSHA256 = "699a84a2ee3faacc0c4097178333b326cfee226a070f7c919d09d0c2e18a18e9"

func TestExactKeyVersionAndGenerationContracts(t *testing.T) {
	valid, err := NewKeyVersion(encryptionResource)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := valid.ProviderValue(); !ok || got != encryptionResource {
		t.Fatalf("provider value = %q, %v", got, ok)
	}
	for _, invalid := range []string{
		"", "primary", "latest", stringsReplaceVersion(encryptionResource, "primary"),
		stringsReplaceVersion(encryptionResource, "latest"), stringsReplaceVersion(encryptionResource, "0"),
		stringsReplaceVersion(encryptionResource, "01"), "projects/project-id/locations/europe-west8/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
	} {
		if _, err := NewKeyVersion(invalid); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("invalid version %q accepted: %v", invalid, err)
		}
	}
	absent := AbsentGeneration()
	if value, ok := absent.ProviderValue(); !ok || value != 0 || !absent.IsAbsent() {
		t.Fatalf("absent generation = %d, %v", value, ok)
	}
	if _, err := NewGeneration(0); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("zero live generation accepted: %v", err)
	}
	live, err := NewGeneration(42)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := live.ProviderValue(); !ok || value != 42 || live.IsAbsent() {
		t.Fatalf("live generation = %d, %v", value, ok)
	}
	if fmt.Sprint(valid, live) != "KeyVersion{REDACTED} Generation{REDACTED}" {
		t.Fatal("resource or generation leaked through formatting")
	}
}

func TestAssociatedDataIsCanonicalAndClosed(t *testing.T) {
	aad := fixtureAAD(t)
	canonical, err := aad.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(canonical)); got != aadGoldenSHA256 {
		t.Fatalf("AAD golden digest = %s", got)
	}
	parsed, err := ParseAssociatedData(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := parsed.Canonical()
	if err != nil || !bytes.Equal(canonical, reencoded) {
		t.Fatal("AAD did not round trip byte-exactly")
	}
	mutations := [][]byte{
		append(clone(canonical), 0),
		append([]byte("BADMAG"), canonical[len(aadMagic):]...),
		clone(canonical),
		clone(canonical),
		clone(canonical),
	}
	mutations[2][len(aadMagic)+2] ^= 1               // domain byte
	mutations[3][len(aadMagic)+2+len(aadDomain)] = 0 // zero profile digest byte-by-byte below
	profileOffset := len(aadMagic) + 2 + len(aadDomain)
	for index := 0; index < 32; index++ {
		mutations[3][profileOffset+index] = 0
	}
	mutations[4][len(aadMagic)] = 0
	mutations[4][len(aadMagic)+1] = 0 // noncanonical zero domain length
	for index, raw := range mutations {
		if _, err := ParseAssociatedData(raw); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("mutation %d accepted: %v", index, err)
		}
	}
	if fmt.Sprint(aad) != "AssociatedData{REDACTED}" {
		t.Fatal("AAD leaked through formatting")
	}
}

func TestEnvelopeRoundTripRejectsSubstitutionAndNoncanonicalInput(t *testing.T) {
	aad, _ := fixtureAAD(t).Canonical()
	encryption, _ := NewKeyVersion(encryptionResource)
	iv := bytes.Repeat([]byte{0x42}, standardIVBytes)
	ciphertext := bytes.Repeat([]byte{0xa5}, standardTagBytes+32)
	envelope, err := NewEnvelope(encryption, iv, standardTagBytes, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := envelope.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(canonical)); got != envelopeGoldenSHA256 {
		t.Fatalf("envelope golden digest = %s", got)
	}
	parsed, err := ParseEnvelope(canonical)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := parsed.Canonical()
	if err != nil || !bytes.Equal(canonical, reencoded) {
		t.Fatal("envelope did not round trip byte-exactly")
	}
	returned := parsed.Ciphertext()
	returned[0] ^= 0xff
	if bytes.Equal(returned, parsed.Ciphertext()) {
		t.Fatal("ciphertext accessor exposed mutable state")
	}
	wrong, _ := NewKeyVersion(stringsReplaceVersion(signingResource, "4"))
	if _, err := NewEnvelope(wrong, iv, standardTagBytes, ciphertext, aad); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("AAD/key substitution accepted: %v", err)
	}
	zeroAlgorithmLength := clone(canonical)
	zeroAlgorithmLength[len(envelopeMagic)] = 0
	zeroAlgorithmLength[len(envelopeMagic)+1] = 0
	wrongAlgorithm := clone(canonical)
	wrongAlgorithm[len(envelopeMagic)+2] ^= 1
	for index, raw := range [][]byte{
		append(clone(canonical), 0), canonical[:len(canonical)-1],
		append([]byte("BADENV"), canonical[len(envelopeMagic):]...),
		zeroAlgorithmLength, wrongAlgorithm,
	} {
		if _, err := ParseEnvelope(raw); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("invalid envelope %d accepted: %v", index, err)
		}
	}
	if _, err := NewEnvelope(encryption, iv[:11], standardTagBytes, ciphertext, aad); !errors.Is(err, ErrInvalidContract) {
		t.Fatal("short IV accepted")
	}
	if _, err := NewEnvelope(encryption, iv, 12, ciphertext, aad); !errors.Is(err, ErrInvalidContract) {
		t.Fatal("nonstandard tag accepted")
	}
	if fmt.Sprint(envelope, parsed) != "Envelope{REDACTED} Envelope{REDACTED}" {
		t.Fatal("envelope leaked through formatting")
	}
}

func TestDeterministicObjectFakeModelsCASAndAmbiguity(t *testing.T) {
	ctx := context.Background()
	store := &fakeObjectStore{next: 40}
	body := fixtureEnvelope(t)
	store.ambiguousSave = true
	if _, err := store.Save(ctx, AbsentGeneration(), body, Checksum(body)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous create = %v", err)
	}
	loaded, err := store.Load(ctx)
	if err != nil || !bytes.Equal(loaded.Body(), body) {
		t.Fatalf("resolve ambiguous create: %v", err)
	}
	if _, err := store.Save(ctx, AbsentGeneration(), body, Checksum(body)); !errors.Is(err, ErrConflict) {
		t.Fatalf("blind recreate = %v", err)
	}
	stale, _ := NewGeneration(39)
	if _, err := store.Save(ctx, stale, body, Checksum(body)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale replace = %v", err)
	}
	wrongChecksum := Checksum([]byte("different"))
	if _, err := store.Save(ctx, loaded.Generation(), body, wrongChecksum); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("bad checksum = %v", err)
	}
	nextBody := append(clone(body), 0x01)
	next, err := store.Save(ctx, loaded.Generation(), nextBody, Checksum(nextBody))
	if err != nil {
		t.Fatal(err)
	}
	store.ambiguousDelete = true
	if err := store.Delete(ctx, next); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous delete = %v", err)
	}
	if _, err := store.Load(ctx); !errors.Is(err, ErrAbsent) {
		t.Fatalf("ambiguous delete did not remove live object: %v", err)
	}
}

func TestDeterministicRawAEADFakeRequiresExactVersionAndIntegrity(t *testing.T) {
	ctx := context.Background()
	version, _ := NewKeyVersion(encryptionResource)
	other, _ := NewKeyVersion(stringsReplaceVersion(encryptionResource, "8"))
	fake := newFakeRawAEAD(t, version)
	aad := fixtureAAD(t)
	plaintextBytes := []byte("bounded session record")
	plaintext, err := NewPlaintext(plaintextBytes)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := fake.Encrypt(ctx, version, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := fake.Decrypt(ctx, version, sealed, aad)
	openedBytes, checksum, ok := opened.ProviderValue()
	if err != nil || !ok || !bytes.Equal(openedBytes, plaintextBytes) || !checksum.Matches(openedBytes) {
		t.Fatalf("decrypt = %q, %v", openedBytes, err)
	}
	if _, err := fake.Encrypt(ctx, other, plaintext, aad); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong encryption version = %v", err)
	}
	if _, err := fake.Decrypt(ctx, other, sealed, aad); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong decryption version = %v", err)
	}
	canonicalAAD, _ := aad.Canonical()
	envelope, err := NewEnvelope(sealed.KeyVersion(), sealed.IV(), sealed.TagLength(), sealed.Ciphertext(), canonicalAAD)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := envelope.Canonical()
	if err != nil || bytes.Contains(canonical, plaintextBytes) {
		t.Fatal("plaintext crossed the stored-envelope boundary")
	}
	oversized := bytes.Repeat([]byte{1}, maximumPlaintextBytes+1)
	if _, err := NewPlaintext(oversized); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("oversized plaintext accepted = %v", err)
	}
	tampered := sealed
	tampered.ciphertext = clone(sealed.ciphertext)
	tampered.ciphertext[0] ^= 1
	if _, err := fake.Decrypt(ctx, version, tampered, aad); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered ciphertext = %v", err)
	}
	if fmt.Sprint(sealed, checksum, plaintext) != "RawCiphertext{REDACTED} CRC32C{REDACTED} Plaintext{REDACTED}" {
		t.Fatal("provider result leaked through formatting")
	}
}

func fixtureAAD(t *testing.T) AssociatedData {
	t.Helper()
	encryption, err1 := NewKeyVersion(encryptionResource)
	signing, err2 := NewKeyVersion(signingResource)
	var profile, thumbprint [32]byte
	for index := range profile {
		profile[index] = byte(index + 1)
		thumbprint[index] = byte(255 - index)
	}
	value, err3 := NewAssociatedData(profile, "yukh-custody-01", "profiles/2bb80d537b1da3e38bd30361aa855686", encryption, signing, thumbprint)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("fixture AAD: %v %v %v", err1, err2, err3)
	}
	return value
}

func fixtureEnvelope(t *testing.T) []byte {
	t.Helper()
	aad, _ := fixtureAAD(t).Canonical()
	version, _ := NewKeyVersion(encryptionResource)
	envelope, err := NewEnvelope(version, bytes.Repeat([]byte{7}, standardIVBytes), standardTagBytes, bytes.Repeat([]byte{9}, standardTagBytes+64), aad)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := envelope.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

type fakeObjectStore struct {
	body            []byte
	generation      uint64
	next            uint64
	ambiguousSave   bool
	ambiguousDelete bool
}

func (f *fakeObjectStore) Load(context.Context) (StoredObject, error) {
	if len(f.body) == 0 {
		return StoredObject{}, ErrAbsent
	}
	generation, _ := NewGeneration(f.generation)
	return NewStoredObject(f.body, generation, Checksum(f.body))
}

func (f *fakeObjectStore) Save(_ context.Context, expected Generation, body []byte, checksum CRC32C) (Generation, error) {
	if !expected.valid() || len(body) == 0 || len(body) > maximumEnvelopeBytes {
		return Generation{}, ErrInvalidContract
	}
	if !checksum.Matches(body) {
		return Generation{}, ErrIntegrity
	}
	if expected.absent {
		if len(f.body) != 0 {
			return Generation{}, ErrConflict
		}
	} else if len(f.body) == 0 || expected.value != f.generation {
		return Generation{}, ErrConflict
	}
	f.next++
	f.generation = f.next
	f.body = clone(body)
	committed, _ := NewGeneration(f.generation)
	if f.ambiguousSave {
		f.ambiguousSave = false
		return Generation{}, ErrAmbiguous
	}
	return committed, nil
}

func (f *fakeObjectStore) Delete(_ context.Context, expected Generation) error {
	if !expected.valid() || expected.absent {
		return ErrInvalidContract
	}
	if len(f.body) == 0 || expected.value != f.generation {
		return ErrConflict
	}
	f.body = nil
	if f.ambiguousDelete {
		f.ambiguousDelete = false
		return ErrAmbiguous
	}
	return nil
}

type fakeRawAEAD struct {
	version KeyVersion
	aead    cipher.AEAD
	iv      []byte
}

func newFakeRawAEAD(t *testing.T, version KeyVersion) *fakeRawAEAD {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeRawAEAD{version: version, aead: aead, iv: bytes.Repeat([]byte{0x44}, aead.NonceSize())}
}

func (f *fakeRawAEAD) Encrypt(_ context.Context, version KeyVersion, plaintext Plaintext, aad AssociatedData) (RawCiphertext, error) {
	if version.value != f.version.value {
		return RawCiphertext{}, ErrConflict
	}
	plaintextBytes, plaintextChecksum, ok := plaintext.ProviderValue()
	aadBytes, err := aad.Canonical()
	if !ok || err != nil || !plaintextChecksum.Matches(plaintextBytes) || len(plaintextBytes)+len(aadBytes) > 8192 {
		return RawCiphertext{}, ErrInvalidContract
	}
	return NewRawCiphertext(version, f.iv, standardTagBytes, f.aead.Seal(nil, f.iv, plaintextBytes, aadBytes))
}

func (f *fakeRawAEAD) Decrypt(_ context.Context, version KeyVersion, sealed RawCiphertext, aad AssociatedData) (Plaintext, error) {
	if version.value != f.version.value || sealed.version.value != f.version.value {
		return Plaintext{}, ErrConflict
	}
	aadBytes, err := aad.Canonical()
	if err != nil {
		return Plaintext{}, ErrInvalidContract
	}
	opened, err := f.aead.Open(nil, sealed.iv, sealed.ciphertext, aadBytes)
	if err != nil {
		return Plaintext{}, ErrIntegrity
	}
	return NewPlaintext(opened)
}

func stringsReplaceVersion(resource, version string) string {
	index := bytes.LastIndexByte([]byte(resource), '/')
	return resource[:index+1] + version
}

var _ ObjectStore = (*fakeObjectStore)(nil)
var _ RawAEAD = (*fakeRawAEAD)(nil)
