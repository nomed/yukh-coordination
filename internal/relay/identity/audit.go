package identity

import (
	"context"
	"crypto/sha256"
	"time"
)

type AuditOperation string

const (
	AuditBootstrap      AuditOperation = "bootstrap"
	AuditAuthentication AuditOperation = "session_authentication"
)

type AuditOutcome string

const (
	AuditAllow       AuditOutcome = "allow"
	AuditDeny        AuditOutcome = "deny"
	AuditUnavailable AuditOutcome = "unavailable"
)

type AuditReason string

const (
	AuditReasonAllowed                 AuditReason = "allowed"
	AuditReasonInvalidCredential       AuditReason = "invalid_credential"
	AuditReasonProofReplay             AuditReason = "proof_replay"
	AuditReasonInactiveSession         AuditReason = "inactive_session"
	AuditReasonVerificationUnavailable AuditReason = "verification_unavailable"
	AuditReasonRegistryUnavailable     AuditReason = "registry_unavailable"
	AuditReasonMaterialCollision       AuditReason = "material_collision"
)

type AuditRecord struct {
	ProfileVersion        int
	OperationID           string
	Operation             AuditOperation
	Outcome               AuditOutcome
	Reason                AuditReason
	DecisionTime          time.Time
	TenantID              string
	PrincipalID           string
	ParticipantInstanceID string
	SessionEpoch          uint64
	DPoPThumbprint        [sha256.Size]byte
	HasDPoPThumbprint     bool
}

type Auditor interface {
	Record(context.Context, AuditRecord) (receipt string, err error)
	Ready(context.Context) error
}
