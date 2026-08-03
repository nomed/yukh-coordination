// Package gcpworkload owns the RFC-0020 Google Cloud workload-custody
// boundary. This foundation contains no Google SDK, credential discovery or
// network implementation.
package gcpworkload

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
)

const (
	aadDomain             = "yukh-gcp-workload-custody-v1"
	aadMagic              = "YGAAD1"
	envelopeMagic         = "YGENV1"
	rawAlgorithm          = "AES_256_GCM"
	maximumAADBytes       = 4096
	maximumPlaintextBytes = 4096
	maximumCiphertext     = maximumPlaintextBytes + 16
	maximumEnvelopeBytes  = 12288
	maximumObjectBytes    = 1024
	maximumReferenceBytes = 512
	standardIVBytes       = 12
	standardTagBytes      = 16
)

var (
	ErrInvalidContract = errors.New("gcp workload custody: invalid contract")
	ErrAbsent          = errors.New("gcp workload custody: object absent")
	ErrConflict        = errors.New("gcp workload custody: revision conflict")
	ErrUnavailable     = errors.New("gcp workload custody: provider unavailable")
	ErrAmbiguous       = errors.New("gcp workload custody: provider outcome ambiguous")
	ErrIntegrity       = errors.New("gcp workload custody: integrity failure")
)

var resourcePart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
var locationPart = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)

// KeyVersion identifies one immutable Cloud KMS CryptoKeyVersion. Formatting
// is deliberately redacted because provider resource names are diagnostics.
type KeyVersion struct{ value string }

func NewKeyVersion(value string) (KeyVersion, error) {
	parts := strings.Split(value, "/")
	if len(value) > maximumReferenceBytes || len(parts) != 10 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" || parts[8] != "cryptoKeyVersions" || !decimalProject(parts[1]) || !locationPart.MatchString(parts[3]) || !resourcePart.MatchString(parts[5]) || !resourcePart.MatchString(parts[7]) || !canonicalPositive(parts[9]) {
		return KeyVersion{}, ErrInvalidContract
	}
	return KeyVersion{value: value}, nil
}

func (KeyVersion) String() string   { return "KeyVersion{REDACTED}" }
func (KeyVersion) GoString() string { return "KeyVersion{REDACTED}" }
func (v KeyVersion) ProviderValue() (string, bool) {
	return v.value, validKeyVersion(v)
}

func validKeyVersion(value KeyVersion) bool {
	parsed, err := NewKeyVersion(value.value)
	return err == nil && parsed.value == value.value
}

// Generation is the sole Cloud Storage CAS authority. The absent generation
// maps to ifGenerationMatch=0; a live generation is always positive.
type Generation struct {
	value  uint64
	absent bool
}

func AbsentGeneration() Generation { return Generation{absent: true} }

func NewGeneration(value uint64) (Generation, error) {
	if value == 0 {
		return Generation{}, ErrInvalidContract
	}
	return Generation{value: value}, nil
}

func (Generation) String() string   { return "Generation{REDACTED}" }
func (Generation) GoString() string { return "Generation{REDACTED}" }
func (g Generation) IsAbsent() bool { return g.valid() && g.absent }
func (g Generation) ProviderValue() (uint64, bool) {
	if !g.valid() {
		return 0, false
	}
	if g.absent {
		return 0, true
	}
	return g.value, true
}
func (g Generation) valid() bool { return g.absent != (g.value != 0) }

// CRC32C is transport-integrity evidence. It is not an authenticator.
type CRC32C struct{ value uint32 }

func Checksum(value []byte) CRC32C {
	return CRC32C{value: crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))}
}

func (CRC32C) String() string          { return "CRC32C{REDACTED}" }
func (CRC32C) GoString() string        { return "CRC32C{REDACTED}" }
func (c CRC32C) ProviderValue() uint32 { return c.value }
func (c CRC32C) Matches(value []byte) bool {
	want := Checksum(value)
	left := []byte{byte(c.value >> 24), byte(c.value >> 16), byte(c.value >> 8), byte(c.value)}
	right := []byte{byte(want.value >> 24), byte(want.value >> 16), byte(want.value >> 8), byte(want.value)}
	return subtle.ConstantTimeCompare(left, right) == 1
}

// AssociatedData is the closed RFC-0020 AES-GCM binding.
type AssociatedData struct {
	profileDigest     [32]byte
	bucket            string
	object            string
	encryptionVersion KeyVersion
	signingVersion    KeyVersion
	signerThumbprint  [32]byte
}

func NewAssociatedData(profileDigest [32]byte, bucket, object string, encryptionVersion, signingVersion KeyVersion, signerThumbprint [32]byte) (AssociatedData, error) {
	if zero32(profileDigest) || zero32(signerThumbprint) || !validBucket(bucket) || !validObject(object) || !validKeyVersion(encryptionVersion) || !validKeyVersion(signingVersion) || encryptionVersion.value == signingVersion.value {
		return AssociatedData{}, ErrInvalidContract
	}
	return AssociatedData{profileDigest: profileDigest, bucket: bucket, object: object, encryptionVersion: encryptionVersion, signingVersion: signingVersion, signerThumbprint: signerThumbprint}, nil
}

func (AssociatedData) String() string   { return "AssociatedData{REDACTED}" }
func (AssociatedData) GoString() string { return "AssociatedData{REDACTED}" }

func (a AssociatedData) Canonical() ([]byte, error) {
	if _, err := NewAssociatedData(a.profileDigest, a.bucket, a.object, a.encryptionVersion, a.signingVersion, a.signerThumbprint); err != nil {
		return nil, ErrInvalidContract
	}
	var out bytes.Buffer
	out.WriteString(aadMagic)
	writeString(&out, aadDomain)
	out.Write(a.profileDigest[:])
	writeString(&out, a.bucket)
	writeString(&out, a.object)
	writeString(&out, a.encryptionVersion.value)
	writeString(&out, a.signingVersion.value)
	out.Write(a.signerThumbprint[:])
	if out.Len() > maximumAADBytes {
		return nil, ErrInvalidContract
	}
	return out.Bytes(), nil
}

func ParseAssociatedData(raw []byte) (AssociatedData, error) {
	if len(raw) == 0 || len(raw) > maximumAADBytes {
		return AssociatedData{}, ErrInvalidContract
	}
	reader := bytes.NewReader(raw)
	magic := make([]byte, len(aadMagic))
	if readFull(reader, magic) != nil || string(magic) != aadMagic {
		return AssociatedData{}, ErrInvalidContract
	}
	domain, ok := readString(reader, 64)
	if !ok || domain != aadDomain {
		return AssociatedData{}, ErrInvalidContract
	}
	var profile, thumbprint [32]byte
	if readFull(reader, profile[:]) != nil {
		return AssociatedData{}, ErrInvalidContract
	}
	bucket, ok1 := readString(reader, 63)
	object, ok2 := readString(reader, maximumObjectBytes)
	encryptionRaw, ok3 := readString(reader, maximumReferenceBytes)
	signingRaw, ok4 := readString(reader, maximumReferenceBytes)
	if !ok1 || !ok2 || !ok3 || !ok4 || readFull(reader, thumbprint[:]) != nil || reader.Len() != 0 {
		return AssociatedData{}, ErrInvalidContract
	}
	encryption, err1 := NewKeyVersion(encryptionRaw)
	signing, err2 := NewKeyVersion(signingRaw)
	value, err3 := NewAssociatedData(profile, bucket, object, encryption, signing, thumbprint)
	if err1 != nil || err2 != nil || err3 != nil {
		return AssociatedData{}, ErrInvalidContract
	}
	canonical, _ := value.Canonical()
	if subtle.ConstantTimeCompare(canonical, raw) != 1 {
		return AssociatedData{}, ErrInvalidContract
	}
	return value, nil
}

// Envelope is the canonical stored ciphertext container. Ciphertext includes
// the AES-GCM authentication tag returned by the exact KMS version.
type Envelope struct {
	encryptionVersion KeyVersion
	iv                []byte
	tagLength         uint16
	ciphertext        []byte
	aad               []byte
}

func NewEnvelope(encryptionVersion KeyVersion, iv []byte, tagLength uint16, ciphertext, aad []byte) (Envelope, error) {
	parsed, err := ParseAssociatedData(aad)
	if err != nil || !validKeyVersion(encryptionVersion) || parsed.encryptionVersion.value != encryptionVersion.value || len(iv) != standardIVBytes || tagLength != standardTagBytes || len(ciphertext) <= int(tagLength) || len(ciphertext) > maximumCiphertext {
		return Envelope{}, ErrInvalidContract
	}
	return Envelope{encryptionVersion: encryptionVersion, iv: clone(iv), tagLength: tagLength, ciphertext: clone(ciphertext), aad: clone(aad)}, nil
}

func (Envelope) String() string   { return "Envelope{REDACTED}" }
func (Envelope) GoString() string { return "Envelope{REDACTED}" }

func (e Envelope) Canonical() ([]byte, error) {
	validated, err := NewEnvelope(e.encryptionVersion, e.iv, e.tagLength, e.ciphertext, e.aad)
	if err != nil {
		return nil, ErrInvalidContract
	}
	var out bytes.Buffer
	out.WriteString(envelopeMagic)
	writeString(&out, rawAlgorithm)
	writeString(&out, validated.encryptionVersion.value)
	_ = binary.Write(&out, binary.BigEndian, validated.tagLength)
	writeBytes16(&out, validated.iv)
	writeBytes32(&out, validated.ciphertext)
	writeBytes32(&out, validated.aad)
	if out.Len() > maximumEnvelopeBytes {
		return nil, ErrInvalidContract
	}
	return out.Bytes(), nil
}

func ParseEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > maximumEnvelopeBytes {
		return Envelope{}, ErrInvalidContract
	}
	reader := bytes.NewReader(raw)
	magic := make([]byte, len(envelopeMagic))
	if readFull(reader, magic) != nil || string(magic) != envelopeMagic {
		return Envelope{}, ErrInvalidContract
	}
	algorithm, ok1 := readString(reader, 32)
	versionRaw, ok2 := readString(reader, maximumReferenceBytes)
	var tag uint16
	if !ok1 || !ok2 || algorithm != rawAlgorithm || binary.Read(reader, binary.BigEndian, &tag) != nil {
		return Envelope{}, ErrInvalidContract
	}
	iv, ok3 := readBytes16(reader, standardIVBytes)
	ciphertext, ok4 := readBytes32(reader, maximumCiphertext)
	aad, ok5 := readBytes32(reader, maximumAADBytes)
	version, err1 := NewKeyVersion(versionRaw)
	value, err2 := NewEnvelope(version, iv, tag, ciphertext, aad)
	if !ok3 || !ok4 || !ok5 || reader.Len() != 0 || err1 != nil || err2 != nil {
		return Envelope{}, ErrInvalidContract
	}
	canonical, _ := value.Canonical()
	if subtle.ConstantTimeCompare(canonical, raw) != 1 {
		return Envelope{}, ErrInvalidContract
	}
	return value, nil
}

func (e Envelope) Ciphertext() []byte     { return clone(e.ciphertext) }
func (e Envelope) AAD() []byte            { return clone(e.aad) }
func (e Envelope) IV() []byte             { return clone(e.iv) }
func (e Envelope) KeyVersion() KeyVersion { return e.encryptionVersion }
func (e Envelope) TagLength() uint16      { return e.tagLength }

// ObjectStore is the exact-generation provider boundary. Implementations must
// never use list, aliases, caches, ranged reads or blind retries.
type ObjectStore interface {
	Load(context.Context) (StoredObject, error)
	Save(context.Context, Generation, []byte, CRC32C) (Generation, error)
	Delete(context.Context, Generation) error
}

type StoredObject struct {
	body       []byte
	generation Generation
	checksum   CRC32C
}

func NewStoredObject(body []byte, generation Generation, checksum CRC32C) (StoredObject, error) {
	if len(body) == 0 || len(body) > maximumEnvelopeBytes || !generation.valid() || generation.absent || !checksum.Matches(body) {
		return StoredObject{}, ErrInvalidContract
	}
	return StoredObject{body: clone(body), generation: generation, checksum: checksum}, nil
}

func (StoredObject) String() string           { return "StoredObject{REDACTED}" }
func (StoredObject) GoString() string         { return "StoredObject{REDACTED}" }
func (o StoredObject) Body() []byte           { return clone(o.body) }
func (o StoredObject) Generation() Generation { return o.generation }
func (o StoredObject) Checksum() CRC32C       { return o.checksum }

// RawAEAD models only exact-version AES-256-GCM raw encryption. Provider
// authentication, retries and response verification belong to a later adapter.
type RawAEAD interface {
	Encrypt(context.Context, KeyVersion, []byte, []byte, CRC32C, CRC32C) (RawCiphertext, error)
	Decrypt(context.Context, KeyVersion, RawCiphertext, []byte, CRC32C) ([]byte, CRC32C, error)
}

type RawCiphertext struct {
	version    KeyVersion
	iv         []byte
	tagLength  uint16
	ciphertext []byte
}

func NewRawCiphertext(version KeyVersion, iv []byte, tagLength uint16, ciphertext []byte) (RawCiphertext, error) {
	if !validKeyVersion(version) || len(iv) != standardIVBytes || tagLength != standardTagBytes || len(ciphertext) <= int(tagLength) || len(ciphertext) > maximumCiphertext {
		return RawCiphertext{}, ErrInvalidContract
	}
	return RawCiphertext{version: version, iv: clone(iv), tagLength: tagLength, ciphertext: clone(ciphertext)}, nil
}

func (RawCiphertext) String() string           { return "RawCiphertext{REDACTED}" }
func (RawCiphertext) GoString() string         { return "RawCiphertext{REDACTED}" }
func (c RawCiphertext) KeyVersion() KeyVersion { return c.version }
func (c RawCiphertext) IV() []byte             { return clone(c.iv) }
func (c RawCiphertext) TagLength() uint16      { return c.tagLength }
func (c RawCiphertext) Ciphertext() []byte     { return clone(c.ciphertext) }

func decimalProject(value string) bool {
	if len(value) < 6 || len(value) > 20 || value[0] == '0' {
		return false
	}
	for _, item := range value {
		if item < '0' || item > '9' {
			return false
		}
	}
	return true
}

func canonicalPositive(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func validBucket(value string) bool {
	return bucketPattern.MatchString(value) && !strings.Contains(value, "..")
}

func validObject(value string) bool {
	if len(value) == 0 || len(value) > maximumObjectBytes || value[0] == '/' || value[len(value)-1] == '/' || strings.Contains(value, "//") {
		return false
	}
	for _, item := range []byte(value) {
		if item < 0x21 || item > 0x7e || item == '\\' {
			return false
		}
	}
	return true
}

func zero32(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func clone(value []byte) []byte { return append([]byte(nil), value...) }

func writeString(out *bytes.Buffer, value string) { writeBytes16(out, []byte(value)) }
func writeBytes16(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint16(len(value)))
	out.Write(value)
}
func writeBytes32(out *bytes.Buffer, value []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	out.Write(value)
}
func readString(reader *bytes.Reader, maximum int) (string, bool) {
	raw, ok := readBytes16(reader, maximum)
	return string(raw), ok
}
func readBytes16(reader *bytes.Reader, maximum int) ([]byte, bool) {
	var size uint16
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || int(size) > maximum || int(size) > reader.Len() {
		return nil, false
	}
	value := make([]byte, size)
	return value, readFull(reader, value) == nil
}
func readBytes32(reader *bytes.Reader, maximum int) ([]byte, bool) {
	var size uint32
	if binary.Read(reader, binary.BigEndian, &size) != nil || size == 0 || uint64(size) > uint64(maximum) || uint64(size) > uint64(reader.Len()) {
		return nil, false
	}
	value := make([]byte, int(size))
	return value, readFull(reader, value) == nil
}
func readFull(reader *bytes.Reader, value []byte) error {
	if reader.Len() < len(value) {
		return ErrInvalidContract
	}
	read, err := reader.Read(value)
	if err != nil || read != len(value) {
		return ErrInvalidContract
	}
	return nil
}
