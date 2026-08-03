// Package clientauth provides the RFC-0014 provider-neutral client custody,
// proof-signing and external-token boundaries. It contains no concrete adapter.
package clientauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	credentialSpecVersion = "0.1"
	maxSafeInteger        = uint64(9_007_199_254_740_991)
	maxReferenceBytes     = 1024
	maxRevisionBytes      = 512
)

var (
	ErrInvalidCredential  = errors.New("client authentication: invalid credential")
	ErrCredentialStore    = errors.New("client authentication: credential store unavailable")
	ErrCredentialMissing  = errors.New("client authentication: credential missing")
	ErrCredentialConflict = errors.New("client authentication: credential revision conflict")
	ErrProofSigner        = errors.New("client authentication: proof signer unavailable")
	ErrProofKeyMissing    = errors.New("client authentication: proof key missing")
	ErrExternalToken      = errors.New("client authentication: external token unavailable")
)

// CredentialStore owns recoverable relay-session custody. Save and Delete are
// exact-revision compare-and-set operations; implementations without CAS do not
// satisfy this port.
type CredentialStore interface {
	Load(context.Context, string) (StoredSession, error)
	Save(context.Context, string, Revision, *SessionRecord) (Revision, error)
	Delete(context.Context, string, Revision) error
}

// SessionRecord is an immutable proof-bound relay session. It contains no
// private key. Credential is an explicit custody-boundary accessor; callers
// must not retain, format or copy its result beyond one adapter operation.
type SessionRecord struct {
	specVersion           string
	participantInstanceID string
	sessionEpoch          uint64
	sessionToken          string
	issuedAt              time.Time
	expiresAt             time.Time
	proofKeyReference     string
	proofJWKThumbprint    [32]byte
}

func NewSessionRecord(participantInstanceID string, sessionEpoch uint64, sessionToken string, issuedAt, expiresAt time.Time, proofKeyReference string, proofJWKThumbprint [32]byte) (*SessionRecord, error) {
	participant, participantErr := uuid.Parse(participantInstanceID)
	decodedToken, tokenErr := base64.RawURLEncoding.Strict().DecodeString(sessionToken)
	if participantErr != nil || participant.Version() != 7 || participant.String() != participantInstanceID || sessionEpoch == 0 || sessionEpoch > maxSafeInteger || tokenErr != nil || len(sessionToken) != 43 || len(decodedToken) != 32 || !validUTCmillisecond(issuedAt) || !validUTCmillisecond(expiresAt) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 15*time.Minute || !validOpaque(proofKeyReference, maxReferenceBytes) || zeroThumbprint(proofJWKThumbprint) {
		return nil, ErrInvalidCredential
	}
	return &SessionRecord{
		specVersion:           credentialSpecVersion,
		participantInstanceID: participantInstanceID,
		sessionEpoch:          sessionEpoch,
		sessionToken:          sessionToken,
		issuedAt:              issuedAt,
		expiresAt:             expiresAt,
		proofKeyReference:     proofKeyReference,
		proofJWKThumbprint:    proofJWKThumbprint,
	}, nil
}

func (r *SessionRecord) SpecVersion() string {
	if r == nil {
		return ""
	}
	return r.specVersion
}
func (r *SessionRecord) ParticipantInstanceID() string {
	if r == nil {
		return ""
	}
	return r.participantInstanceID
}
func (r *SessionRecord) SessionEpoch() uint64 {
	if r == nil {
		return 0
	}
	return r.sessionEpoch
}
func (r *SessionRecord) IssuedAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.issuedAt
}
func (r *SessionRecord) ExpiresAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.expiresAt
}
func (r *SessionRecord) Credential() string {
	if r == nil {
		return ""
	}
	return r.sessionToken
}
func (r *SessionRecord) ProofKeyReference() string {
	if r == nil {
		return ""
	}
	return r.proofKeyReference
}
func (r *SessionRecord) ProofJWKThumbprint() [32]byte {
	if r == nil {
		return [32]byte{}
	}
	return r.proofJWKThumbprint
}
func (*SessionRecord) String() string   { return "SessionRecord{REDACTED}" }
func (*SessionRecord) GoString() string { return "SessionRecord{REDACTED}" }

func (r *SessionRecord) clone() (*SessionRecord, error) {
	if !validSessionRecord(r) {
		return nil, ErrInvalidCredential
	}
	copy := *r
	return &copy, nil
}

func validSessionRecord(r *SessionRecord) bool {
	if r == nil {
		return false
	}
	validated, err := NewSessionRecord(r.participantInstanceID, r.sessionEpoch, r.sessionToken, r.issuedAt, r.expiresAt, r.proofKeyReference, r.proofJWKThumbprint)
	return err == nil && r.specVersion == validated.specVersion
}

// Revision is an opaque credential-store CAS revision. Its value is deliberately
// absent from formatting and output.
type Revision struct {
	value  string
	absent bool
}

func AbsentRevision() Revision { return Revision{absent: true} }

func NewRevision(value string) (Revision, error) {
	if !validOpaque(value, maxRevisionBytes) {
		return Revision{}, ErrInvalidCredential
	}
	return Revision{value: value}, nil
}

func (r Revision) valid() bool    { return r.absent != (r.value != "") }
func (Revision) String() string   { return "Revision{REDACTED}" }
func (Revision) GoString() string { return "Revision{REDACTED}" }

// IsAbsent reports only the explicit absent revision used for first creation.
// A zero or otherwise invalid Revision is not absent.
func (r Revision) IsAbsent() bool { return r.valid() && r.absent }

// ProviderValue is restricted to a credential-store adapter's CAS call. The
// boolean is false for the explicit absent revision.
func (r Revision) ProviderValue() (string, bool) {
	if !r.valid() || r.absent {
		return "", false
	}
	return r.value, true
}

// StoredSession couples one validated record to the exact store revision that
// must be used for its next mutation.
type StoredSession struct {
	record   *SessionRecord
	revision Revision
}

func NewStoredSession(record *SessionRecord, revision Revision) (StoredSession, error) {
	copy, err := record.clone()
	if err != nil || !revision.valid() || revision.absent {
		return StoredSession{}, ErrInvalidCredential
	}
	return StoredSession{record: copy, revision: revision}, nil
}

func (s StoredSession) Record() (*SessionRecord, error) { return s.record.clone() }
func (s StoredSession) Revision() Revision              { return s.revision }
func (StoredSession) String() string                    { return "StoredSession{REDACTED}" }
func (StoredSession) GoString() string                  { return "StoredSession{REDACTED}" }

func validUTCmillisecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func validOpaque(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && asciiVisible(value)
}

func asciiVisible(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func zeroThumbprint(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func validateProfile(profile string) error {
	if profile == "" || len(profile) > 128 {
		return ErrInvalidCredential
	}
	for _, r := range profile {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ErrInvalidCredential
		}
	}
	return nil
}

func sanitizeStoreError(err error) error {
	switch {
	case errors.Is(err, ErrCredentialMissing):
		return ErrCredentialMissing
	case errors.Is(err, ErrCredentialConflict):
		return ErrCredentialConflict
	default:
		return ErrCredentialStore
	}
}

var _ fmt.Stringer = (*SessionRecord)(nil)
