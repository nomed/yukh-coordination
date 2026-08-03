package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	CheckpointProfile    = "yukh-security-audit-checkpoint/v1"
	KeyStatementProfile  = "yukh-security-audit-verification-key/v1"
	ExportProfile        = "yukh-security-audit-checkpoint-export/v1"
	WitnessProfile       = "yukh-security-audit-witness/v1"
	CheckpointAlgorithm  = "Ed25519"
	MaxCheckpointBytes   = 4096
	MaxKeyStatementBytes = 4096
	MaxWitnessBytes      = 16384
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Checkpoint struct {
	LedgerID             string
	TreeSize             uint64
	RootHash             Hash
	ChainHead            Hash
	IssuedAt             time.Time
	Algorithm            string
	KeyID                string
	PredecessorReference string
}

type SignedCheckpoint struct {
	Checkpoint Checkpoint
	Canonical  []byte
	Signature  []byte
	Reference  string
}

type VerificationKeyStatement struct {
	Version          uint64
	KeyID            string
	Algorithm        string
	PublicKey        ed25519.PublicKey
	ActiveFrom       time.Time
	RetiredAt        *time.Time
	CompromisedFrom  *time.Time
	CompromisedUntil *time.Time
	IssuedAt         time.Time
}

type SignedVerificationKeyStatement struct {
	Statement VerificationKeyStatement
	Canonical []byte
	Signature []byte
}

type CheckpointTrust string

const (
	CheckpointTrusted       CheckpointTrust = "trusted"
	CheckpointIndeterminate CheckpointTrust = "indeterminate"
)

type CheckpointSigningSelection struct {
	KeyID     string
	Algorithm string
}

type CheckpointSigner interface {
	Select(context.Context) (CheckpointSigningSelection, error)
	Sign(context.Context, CheckpointSigningSelection, []byte) ([]byte, error)
}

type CheckpointExport struct {
	Profile               string `json:"profile"`
	Checkpoint            string `json:"checkpoint"`
	Signature             string `json:"signature"`
	CheckpointReference   string `json:"checkpoint_reference"`
	KeyStatement          string `json:"key_statement"`
	KeyStatementSignature string `json:"key_statement_signature"`
}

type WitnessAcknowledgement struct {
	WitnessID           string
	CheckpointReference string
	Canonical           []byte
}

type CheckpointWitness interface {
	Witness(context.Context, []byte) (WitnessAcknowledgement, error)
}

type WitnessVerifier interface {
	VerifyWitness(context.Context, WitnessAcknowledgement) error
}

type canonicalCheckpoint struct {
	Profile              string `json:"profile"`
	LedgerID             string `json:"ledger_id"`
	TreeSize             uint64 `json:"tree_size"`
	RootHash             string `json:"root_hash"`
	ChainHead            string `json:"chain_head"`
	IssuedAt             string `json:"issued_at"`
	Algorithm            string `json:"algorithm"`
	KeyID                string `json:"key_id"`
	PredecessorReference string `json:"predecessor_checkpoint_reference,omitempty"`
}

type canonicalKeyStatement struct {
	Profile          string `json:"profile"`
	Version          uint64 `json:"version"`
	KeyID            string `json:"key_id"`
	Algorithm        string `json:"algorithm"`
	PublicKey        string `json:"public_key"`
	ActiveFrom       string `json:"active_from"`
	RetiredAt        string `json:"retired_at,omitempty"`
	CompromisedFrom  string `json:"compromised_from,omitempty"`
	CompromisedUntil string `json:"compromised_until,omitempty"`
	IssuedAt         string `json:"issued_at"`
}

type canonicalWitnessAcknowledgement struct {
	Profile             string `json:"profile"`
	WitnessID           string `json:"witness_id"`
	CheckpointReference string `json:"checkpoint_reference"`
	ObservedAt          string `json:"observed_at"`
	Algorithm           string `json:"algorithm"`
	KeyID               string `json:"key_id"`
	Signature           string `json:"signature"`
}

func CanonicalCheckpoint(value Checkpoint) ([]byte, error) {
	if !validCheckpoint(value) {
		return nil, ErrUnavailable
	}
	canonical := canonicalCheckpoint{Profile: CheckpointProfile, LedgerID: value.LedgerID, TreeSize: value.TreeSize,
		RootHash: encodeDigest(value.RootHash), ChainHead: encodeDigest(value.ChainHead), IssuedAt: formatMillis(value.IssuedAt),
		Algorithm: value.Algorithm, KeyID: value.KeyID, PredecessorReference: value.PredecessorReference}
	return canonicalJSON(canonical, MaxCheckpointBytes)
}

func ParseCanonicalCheckpoint(raw []byte) (Checkpoint, error) {
	var value canonicalCheckpoint
	if !decodeCanonical(raw, MaxCheckpointBytes, &value) || value.Profile != CheckpointProfile {
		return Checkpoint{}, ErrUnavailable
	}
	root, ok := decodeHash(value.RootHash)
	if !ok {
		return Checkpoint{}, ErrUnavailable
	}
	head, ok := decodeHash(value.ChainHead)
	if !ok {
		return Checkpoint{}, ErrUnavailable
	}
	issued, ok := parseMillis(value.IssuedAt)
	if !ok {
		return Checkpoint{}, ErrUnavailable
	}
	result := Checkpoint{LedgerID: value.LedgerID, TreeSize: value.TreeSize, RootHash: root, ChainHead: head,
		IssuedAt: issued, Algorithm: value.Algorithm, KeyID: value.KeyID, PredecessorReference: value.PredecessorReference}
	if !validCheckpoint(result) {
		return Checkpoint{}, ErrUnavailable
	}
	reencoded, err := CanonicalCheckpoint(result)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return Checkpoint{}, ErrUnavailable
	}
	return result, nil
}

func CheckpointPreimage(canonical []byte) ([]byte, error) {
	if _, err := ParseCanonicalCheckpoint(canonical); err != nil {
		return nil, ErrUnavailable
	}
	return append([]byte("yukh-coordination:audit-checkpoint:v1\n"), canonical...), nil
}

func CheckpointReference(canonical, signature []byte) (string, error) {
	if _, err := ParseCanonicalCheckpoint(canonical); err != nil || len(signature) != ed25519.SignatureSize {
		return "", ErrUnavailable
	}
	preimage := append([]byte("yukh-coordination:audit-checkpoint-reference:v1\n"), canonical...)
	preimage = append(preimage, signature...)
	digest := sha256.Sum256(preimage)
	return "audit-checkpoint:" + encodeDigest(digest), nil
}

func CanonicalVerificationKeyStatement(value VerificationKeyStatement) ([]byte, error) {
	if !validKeyStatement(value) {
		return nil, ErrUnavailable
	}
	canonical := canonicalKeyStatement{Profile: KeyStatementProfile, Version: value.Version, KeyID: value.KeyID,
		Algorithm: value.Algorithm, PublicKey: base64.RawURLEncoding.EncodeToString(value.PublicKey),
		ActiveFrom: formatMillis(value.ActiveFrom), IssuedAt: formatMillis(value.IssuedAt)}
	if value.RetiredAt != nil {
		canonical.RetiredAt = formatMillis(*value.RetiredAt)
	}
	if value.CompromisedFrom != nil {
		canonical.CompromisedFrom = formatMillis(*value.CompromisedFrom)
	}
	if value.CompromisedUntil != nil {
		canonical.CompromisedUntil = formatMillis(*value.CompromisedUntil)
	}
	return canonicalJSON(canonical, MaxKeyStatementBytes)
}

func ParseCanonicalVerificationKeyStatement(raw []byte) (VerificationKeyStatement, error) {
	var value canonicalKeyStatement
	if !decodeCanonical(raw, MaxKeyStatementBytes, &value) || value.Profile != KeyStatementProfile {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(value.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	active, ok := parseMillis(value.ActiveFrom)
	if !ok {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	issued, ok := parseMillis(value.IssuedAt)
	if !ok {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	result := VerificationKeyStatement{Version: value.Version, KeyID: value.KeyID, Algorithm: value.Algorithm,
		PublicKey: ed25519.PublicKey(append([]byte(nil), publicKey...)), ActiveFrom: active, IssuedAt: issued}
	if value.RetiredAt != "" {
		parsed, ok := parseMillis(value.RetiredAt)
		if !ok {
			return VerificationKeyStatement{}, ErrUnavailable
		}
		result.RetiredAt = &parsed
	}
	if value.CompromisedFrom != "" {
		parsed, ok := parseMillis(value.CompromisedFrom)
		if !ok {
			return VerificationKeyStatement{}, ErrUnavailable
		}
		result.CompromisedFrom = &parsed
	}
	if value.CompromisedUntil != "" {
		parsed, ok := parseMillis(value.CompromisedUntil)
		if !ok {
			return VerificationKeyStatement{}, ErrUnavailable
		}
		result.CompromisedUntil = &parsed
	}
	if !validKeyStatement(result) {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	reencoded, err := CanonicalVerificationKeyStatement(result)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	return result, nil
}

func KeyStatementPreimage(canonical []byte) ([]byte, error) {
	if _, err := ParseCanonicalVerificationKeyStatement(canonical); err != nil {
		return nil, ErrUnavailable
	}
	return append([]byte("yukh-coordination:audit-verification-key:v1\n"), canonical...), nil
}

func VerifyKeyStatement(authority ed25519.PublicKey, canonical, signature []byte) (VerificationKeyStatement, error) {
	if len(authority) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	statement, err := ParseCanonicalVerificationKeyStatement(canonical)
	if err != nil {
		return VerificationKeyStatement{}, err
	}
	preimage, _ := KeyStatementPreimage(canonical)
	if !ed25519.Verify(authority, preimage, signature) {
		return VerificationKeyStatement{}, ErrUnavailable
	}
	return statement, nil
}

func VerifySignedCheckpoint(signed SignedCheckpoint, statement VerificationKeyStatement) (CheckpointTrust, error) {
	parsed, err := ParseCanonicalCheckpoint(signed.Canonical)
	if err != nil || parsed != signed.Checkpoint || parsed.KeyID != statement.KeyID || parsed.Algorithm != CheckpointAlgorithm || statement.Algorithm != CheckpointAlgorithm || len(signed.Signature) != ed25519.SignatureSize {
		return "", ErrUnavailable
	}
	preimage, _ := CheckpointPreimage(signed.Canonical)
	if !ed25519.Verify(statement.PublicKey, preimage, signed.Signature) {
		return "", ErrUnavailable
	}
	reference, err := CheckpointReference(signed.Canonical, signed.Signature)
	if err != nil || (signed.Reference != "" && signed.Reference != reference) {
		return "", ErrUnavailable
	}
	if parsed.IssuedAt.Before(statement.ActiveFrom) || (statement.RetiredAt != nil && !parsed.IssuedAt.Before(*statement.RetiredAt)) {
		return "", ErrUnavailable
	}
	if statement.CompromisedFrom != nil && !parsed.IssuedAt.Before(*statement.CompromisedFrom) && (statement.CompromisedUntil == nil || parsed.IssuedAt.Before(*statement.CompromisedUntil)) {
		return CheckpointIndeterminate, nil
	}
	return CheckpointTrusted, nil
}

func CanonicalCheckpointExport(signed SignedCheckpoint, key SignedVerificationKeyStatement) ([]byte, error) {
	if _, err := ParseCanonicalCheckpoint(signed.Canonical); err != nil || len(signed.Signature) != ed25519.SignatureSize {
		return nil, ErrUnavailable
	}
	if _, err := ParseCanonicalVerificationKeyStatement(key.Canonical); err != nil || len(key.Signature) != ed25519.SignatureSize {
		return nil, ErrUnavailable
	}
	reference, err := CheckpointReference(signed.Canonical, signed.Signature)
	if err != nil {
		return nil, err
	}
	value := CheckpointExport{Profile: ExportProfile, Checkpoint: base64.RawURLEncoding.EncodeToString(signed.Canonical), Signature: base64.RawURLEncoding.EncodeToString(signed.Signature), CheckpointReference: reference,
		KeyStatement: base64.RawURLEncoding.EncodeToString(key.Canonical), KeyStatementSignature: base64.RawURLEncoding.EncodeToString(key.Signature)}
	return canonicalJSON(value, MaxWitnessBytes)
}

func ValidateWitnessAcknowledgement(value WitnessAcknowledgement) error {
	if !keyIDPattern.MatchString(value.WitnessID) || !validCheckpointReference(value.CheckpointReference) || len(value.Canonical) == 0 || len(value.Canonical) > MaxWitnessBytes {
		return ErrUnavailable
	}
	var canonical canonicalWitnessAcknowledgement
	if !decodeCanonical(value.Canonical, MaxWitnessBytes, &canonical) || canonical.Profile != WitnessProfile || canonical.WitnessID != value.WitnessID || canonical.CheckpointReference != value.CheckpointReference || !keyIDPattern.MatchString(canonical.KeyID) || canonical.Algorithm != CheckpointAlgorithm {
		return ErrUnavailable
	}
	if _, ok := parseMillis(canonical.ObservedAt); !ok {
		return ErrUnavailable
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(canonical.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrUnavailable
	}
	return nil
}

func validCheckpoint(value Checkpoint) bool {
	if _, err := canonicalV7(value.LedgerID); err != nil || value.TreeSize == 0 || value.TreeSize > MaxJSONSafeSequence || value.IssuedAt.Location() != time.UTC || !value.IssuedAt.Equal(value.IssuedAt.Truncate(time.Millisecond)) || value.Algorithm != CheckpointAlgorithm || !keyIDPattern.MatchString(value.KeyID) {
		return false
	}
	return value.PredecessorReference == "" || validCheckpointReference(value.PredecessorReference)
}

func validKeyStatement(value VerificationKeyStatement) bool {
	if value.Version == 0 || value.Version > MaxJSONSafeSequence || !keyIDPattern.MatchString(value.KeyID) || value.Algorithm != CheckpointAlgorithm || len(value.PublicKey) != ed25519.PublicKeySize || !validMillis(value.ActiveFrom) || !validMillis(value.IssuedAt) || value.IssuedAt.Before(value.ActiveFrom) {
		return false
	}
	if value.RetiredAt != nil && (!validMillis(*value.RetiredAt) || !value.RetiredAt.After(value.ActiveFrom)) {
		return false
	}
	if value.CompromisedFrom != nil && !validMillis(*value.CompromisedFrom) {
		return false
	}
	if value.CompromisedUntil != nil && (value.CompromisedFrom == nil || !validMillis(*value.CompromisedUntil) || !value.CompromisedUntil.After(*value.CompromisedFrom)) {
		return false
	}
	return true
}

func validCheckpointReference(value string) bool {
	const prefix = "audit-checkpoint:"
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	return validDigestText(value[len(prefix):])
}

func validMillis(value time.Time) bool {
	return value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}
func formatMillis(value time.Time) string { return value.Format("2006-01-02T15:04:05.000Z") }
func parseMillis(value string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return parsed, err == nil && formatMillis(parsed) == value
}

func canonicalJSON(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnavailable
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) == 0 || len(canonical) > limit {
		return nil, ErrUnavailable
	}
	return canonical, nil
}

func decodeCanonical(raw []byte, limit int, target any) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	normalized, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(normalized, raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func decodeHash(value string) (Hash, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return Hash{}, false
	}
	var result Hash
	copy(result[:], raw)
	return result, true
}
