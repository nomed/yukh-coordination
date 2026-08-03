package gcpworkload

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
)

const (
	profileDigestDomain = "yukh-gcp-profile-v1\x00"
	sessionMagic        = "YGSES1"
)

// OperationIDSource supplies the random 128-bit marker used to resolve a lost
// Cloud Storage write response without blindly repeating the mutation.
type OperationIDSource interface {
	NewOperationID() ([16]byte, error)
}

type CryptoOperationIDs struct{}

func (CryptoOperationIDs) NewOperationID() ([16]byte, error) {
	var value [16]byte
	_, err := io.ReadFull(rand.Reader, value[:])
	return value, err
}

// CredentialStore composes the exact-object and exact-key boundaries into the
// existing provider-neutral RFC-0014 port. It owns no client construction,
// identity discovery, KMS key lifecycle or fallback.
type CredentialStore struct {
	profile      string
	object       CredentialObjectStore
	aead         RawAEAD
	aad          AssociatedData
	aadCanonical []byte
	operations   OperationIDSource
}

// CredentialObjectStore adds the live-generation verification read required
// before a successful credential mutation may be reported.
type CredentialObjectStore interface {
	ObjectStore
	LoadGeneration(context.Context, Generation) (StoredObject, error)
}

func NewCredentialStore(profile string, object CredentialObjectStore, aead RawAEAD, aad AssociatedData, operations OperationIDSource) (*CredentialStore, error) {
	canonical, err := aad.Canonical()
	digest := sha256.Sum256([]byte(profileDigestDomain + profile))
	if !validProfileName(profile) || object == nil || aead == nil || operations == nil || err != nil || subtle.ConstantTimeCompare(digest[:], aad.profileDigest[:]) != 1 {
		return nil, ErrInvalidContract
	}
	return &CredentialStore{profile: profile, object: object, aead: aead, aad: aad, aadCanonical: canonical, operations: operations}, nil
}

func (s *CredentialStore) Load(ctx context.Context, profile string) (clientauth.StoredSession, error) {
	if !s.validProfile(profile) {
		return clientauth.StoredSession{}, clientauth.ErrInvalidCredential
	}
	stored, err := s.object.Load(ctx)
	if err != nil {
		return clientauth.StoredSession{}, publicStoreError(err)
	}
	_, record, err := s.open(ctx, stored)
	if err != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialStore
	}
	revision, err := revisionFromGeneration(stored.Generation())
	if err != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialStore
	}
	result, err := clientauth.NewStoredSession(record, revision)
	if err != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialStore
	}
	return result, nil
}

func (s *CredentialStore) Save(ctx context.Context, profile string, expected clientauth.Revision, record *clientauth.SessionRecord) (clientauth.Revision, error) {
	if !s.validProfile(profile) || !s.validRecord(record) {
		return clientauth.Revision{}, clientauth.ErrInvalidCredential
	}
	generation, err := generationFromRevision(expected)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrInvalidCredential
	}
	operationID, err := s.operations.NewOperationID()
	if err != nil || zero16(operationID) {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	encoded, err := encodeSession(operationID, record)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrInvalidCredential
	}
	plaintext, err := NewPlaintext(encoded)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrInvalidCredential
	}
	ciphertext, err := s.aead.Encrypt(ctx, s.aad.encryptionVersion, plaintext, s.aad)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	envelope, err := NewEnvelope(ciphertext.KeyVersion(), ciphertext.IV(), ciphertext.TagLength(), ciphertext.Ciphertext(), s.aadCanonical)
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	body, err := envelope.Canonical()
	if err != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	written, saveErr := s.object.Save(ctx, generation, body, Checksum(body))
	if saveErr != nil && !errors.Is(saveErr, ErrAmbiguous) {
		return clientauth.Revision{}, publicStoreError(saveErr)
	}
	var verified StoredObject
	var verifyErr error
	if saveErr == nil {
		verified, verifyErr = s.object.LoadGeneration(ctx, written)
	} else {
		verified, verifyErr = s.object.Load(ctx)
	}
	if verifyErr != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	observedID, observedRecord, openErr := s.open(ctx, verified)
	if openErr != nil {
		return clientauth.Revision{}, clientauth.ErrCredentialStore
	}
	if subtle.ConstantTimeCompare(operationID[:], observedID[:]) != 1 || !sameRecord(record, observedRecord) {
		return clientauth.Revision{}, clientauth.ErrCredentialConflict
	}
	if saveErr == nil && !sameGeneration(written, verified.Generation()) {
		return clientauth.Revision{}, clientauth.ErrCredentialConflict
	}
	return revisionFromGeneration(verified.Generation())
}

func (s *CredentialStore) Delete(ctx context.Context, profile string, expected clientauth.Revision) error {
	if !s.validProfile(profile) {
		return clientauth.ErrInvalidCredential
	}
	generation, err := generationFromRevision(expected)
	if err != nil || generation.IsAbsent() {
		return clientauth.ErrInvalidCredential
	}
	err = s.object.Delete(ctx, generation)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrAmbiguous) {
		return publicStoreError(err)
	}
	live, loadErr := s.object.Load(ctx)
	if errors.Is(loadErr, ErrAbsent) {
		return nil
	}
	if loadErr != nil {
		return clientauth.ErrCredentialStore
	}
	if !sameGeneration(generation, live.Generation()) {
		return clientauth.ErrCredentialConflict
	}
	if retryErr := s.object.Delete(ctx, generation); retryErr != nil {
		return publicStoreError(retryErr)
	}
	return nil
}

func (s *CredentialStore) open(ctx context.Context, stored StoredObject) ([16]byte, *clientauth.SessionRecord, error) {
	envelope, err := ParseEnvelope(stored.Body())
	if err != nil || !validKeyVersion(envelope.KeyVersion()) || envelope.KeyVersion().value != s.aad.encryptionVersion.value || subtle.ConstantTimeCompare(envelope.AAD(), s.aadCanonical) != 1 {
		return [16]byte{}, nil, ErrIntegrity
	}
	raw, err := NewRawCiphertext(envelope.KeyVersion(), envelope.IV(), envelope.TagLength(), envelope.Ciphertext())
	if err != nil {
		return [16]byte{}, nil, ErrIntegrity
	}
	plaintext, err := s.aead.Decrypt(ctx, s.aad.encryptionVersion, raw, s.aad)
	if err != nil {
		return [16]byte{}, nil, ErrIntegrity
	}
	value, checksum, ok := plaintext.ProviderValue()
	if !ok || !checksum.Matches(value) {
		return [16]byte{}, nil, ErrIntegrity
	}
	operationID, record, err := decodeSession(value)
	if err != nil || !s.validRecord(record) {
		return [16]byte{}, nil, ErrIntegrity
	}
	return operationID, record, nil
}

func (s *CredentialStore) validProfile(profile string) bool {
	return s != nil && s.object != nil && s.aead != nil && s.operations != nil && validProfileName(profile) && profile == s.profile
}

func validProfileName(profile string) bool {
	if profile == "" || len(profile) > 128 {
		return false
	}
	for _, item := range profile {
		if !(item >= 'a' && item <= 'z' || item >= 'A' && item <= 'Z' || item >= '0' && item <= '9' || item == '-' || item == '_' || item == '.') {
			return false
		}
	}
	return true
}

func (s *CredentialStore) validRecord(record *clientauth.SessionRecord) bool {
	if record == nil || record.ProofKeyReference() != s.aad.signingVersion.value {
		return false
	}
	thumbprint := record.ProofJWKThumbprint()
	return subtle.ConstantTimeCompare(thumbprint[:], s.aad.signerThumbprint[:]) == 1
}

func encodeSession(operationID [16]byte, record *clientauth.SessionRecord) ([]byte, error) {
	if record == nil || zero16(operationID) {
		return nil, ErrInvalidContract
	}
	var out bytes.Buffer
	out.WriteString(sessionMagic)
	out.Write(operationID[:])
	writeString(&out, record.SpecVersion())
	writeString(&out, record.ParticipantInstanceID())
	_ = binary.Write(&out, binary.BigEndian, record.SessionEpoch())
	writeString(&out, record.Credential())
	_ = binary.Write(&out, binary.BigEndian, record.IssuedAt().UnixMilli())
	_ = binary.Write(&out, binary.BigEndian, record.ExpiresAt().UnixMilli())
	writeString(&out, record.ProofKeyReference())
	thumbprint := record.ProofJWKThumbprint()
	out.Write(thumbprint[:])
	if out.Len() > maximumPlaintextBytes {
		return nil, ErrInvalidContract
	}
	return out.Bytes(), nil
}

func decodeSession(raw []byte) ([16]byte, *clientauth.SessionRecord, error) {
	if len(raw) == 0 || len(raw) > maximumPlaintextBytes {
		return [16]byte{}, nil, ErrInvalidContract
	}
	reader := bytes.NewReader(raw)
	magic := make([]byte, len(sessionMagic))
	var operationID [16]byte
	if readFull(reader, magic) != nil || string(magic) != sessionMagic || readFull(reader, operationID[:]) != nil || zero16(operationID) {
		return [16]byte{}, nil, ErrInvalidContract
	}
	spec, ok1 := readString(reader, 16)
	participant, ok2 := readString(reader, 64)
	var epoch uint64
	if !ok1 || !ok2 || spec != "0.1" || binary.Read(reader, binary.BigEndian, &epoch) != nil {
		return [16]byte{}, nil, ErrInvalidContract
	}
	token, ok3 := readString(reader, 64)
	var issuedMillis, expiresMillis int64
	if !ok3 || binary.Read(reader, binary.BigEndian, &issuedMillis) != nil || binary.Read(reader, binary.BigEndian, &expiresMillis) != nil {
		return [16]byte{}, nil, ErrInvalidContract
	}
	proofReference, ok4 := readString(reader, maximumReferenceBytes)
	var thumbprint [32]byte
	if !ok4 || readFull(reader, thumbprint[:]) != nil || reader.Len() != 0 {
		return [16]byte{}, nil, ErrInvalidContract
	}
	record, err := clientauth.NewSessionRecord(participant, epoch, token, time.UnixMilli(issuedMillis).UTC(), time.UnixMilli(expiresMillis).UTC(), proofReference, thumbprint)
	if err != nil {
		return [16]byte{}, nil, ErrInvalidContract
	}
	return operationID, record, nil
}

func generationFromRevision(revision clientauth.Revision) (Generation, error) {
	if revision.IsAbsent() {
		return AbsentGeneration(), nil
	}
	value, ok := revision.ProviderValue()
	if !ok || !canonicalPositive(value) {
		return Generation{}, ErrInvalidContract
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return Generation{}, ErrInvalidContract
	}
	return NewGeneration(parsed)
}

func revisionFromGeneration(generation Generation) (clientauth.Revision, error) {
	value, ok := generation.ProviderValue()
	if !ok || generation.IsAbsent() {
		return clientauth.Revision{}, ErrInvalidContract
	}
	return clientauth.NewRevision(strconv.FormatUint(value, 10))
}

func sameGeneration(left, right Generation) bool {
	l, lok := left.ProviderValue()
	r, rok := right.ProviderValue()
	return lok && rok && left.IsAbsent() == right.IsAbsent() && l == r
}

func sameRecord(left, right *clientauth.SessionRecord) bool {
	if left == nil || right == nil {
		return false
	}
	lThumb, rThumb := left.ProofJWKThumbprint(), right.ProofJWKThumbprint()
	return left.SpecVersion() == right.SpecVersion() && left.ParticipantInstanceID() == right.ParticipantInstanceID() && left.SessionEpoch() == right.SessionEpoch() && subtle.ConstantTimeCompare([]byte(left.Credential()), []byte(right.Credential())) == 1 && left.IssuedAt().Equal(right.IssuedAt()) && left.ExpiresAt().Equal(right.ExpiresAt()) && left.ProofKeyReference() == right.ProofKeyReference() && subtle.ConstantTimeCompare(lThumb[:], rThumb[:]) == 1
}

func publicStoreError(err error) error {
	switch {
	case errors.Is(err, ErrAbsent):
		return clientauth.ErrCredentialMissing
	case errors.Is(err, ErrConflict):
		return clientauth.ErrCredentialConflict
	default:
		return clientauth.ErrCredentialStore
	}
}

func zero16(value [16]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
