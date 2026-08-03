package identity

import (
	"crypto/sha256"
	"errors"
	"time"
)

var (
	ErrRegistryInvalid     = errors.New("identity registry invalid input")
	ErrRegistryUnavailable = errors.New("identity registry unavailable")
	ErrProofReplay         = errors.New("identity proof replay")
	ErrSessionNotFound     = errors.New("identity session not found")
	ErrSessionConflict     = errors.New("identity session conflict")
	ErrRegistryFenced      = errors.New("identity registry fenced")
	ErrClockRollback       = errors.New("identity registry clock rollback")
	ErrEpochExhausted      = errors.New("identity session epoch exhausted")
)

type SessionState string

const (
	SessionPending   SessionState = "pending"
	SessionActive    SessionState = "active"
	SessionRevoked   SessionState = "revoked"
	SessionExpired   SessionState = "expired"
	SessionAbandoned SessionState = "abandoned"
)

type ProofPurpose string

const (
	ProofBootstrap      ProofPurpose = "bootstrap"
	ProofAuthentication ProofPurpose = "authentication"
)

type SessionKey struct {
	TenantID              string
	ParticipantInstanceID string
	SessionEpoch          uint64
}

type PendingSession struct {
	TenantID              string
	PrincipalID           string
	ParticipantInstanceID string
	SessionEpoch          uint64
	TokenDigest           [sha256.Size]byte
	DPoPThumbprint        [sha256.Size]byte
	IssuedAt              time.Time
	ExpiresAt             time.Time
	BootstrapOperationID  string
}

type ActiveSession struct {
	TenantID              string
	PrincipalID           string
	ParticipantInstanceID string
	SessionEpoch          uint64
	DPoPThumbprint        [sha256.Size]byte
	ExpiresAt             time.Time
}

type BootstrapReservation struct {
	Session  PendingSession
	ProofJTI string
	ProofIAT time.Time
}

type AuthenticationReservation struct {
	TokenDigest    [sha256.Size]byte
	DPoPThumbprint [sha256.Size]byte
	ProofJTI       string
	ProofIAT       time.Time
}

type Revocation struct {
	OperationID      string
	Key              SessionKey
	Reason           string
	AuthorityReceipt string
}

type EpochFloor struct {
	TenantID    string
	PrincipalID string
	Epoch       uint64
}

type RegistryStatus struct {
	DatabaseID    string
	SchemaVersion int
	FenceState    string
	WallHighWater time.Time
}

type RecoverySnapshot struct {
	DatabaseID    string
	WallHighWater time.Time
	EpochFloors   []EpochFloor
}
