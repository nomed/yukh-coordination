package identity

import (
	"context"
	"crypto/sha256"
	"time"
)

type AuditOperation string

const (
	AuditBootstrap             AuditOperation = "bootstrap"
	AuditAuthentication        AuditOperation = "session_authentication"
	AuditRevocation            AuditOperation = "revocation"
	AuditJWKSRefresh           AuditOperation = "jwks_refresh"
	AuditRestoreFence          AuditOperation = "restore_fence"
	AuditCheckpoint            AuditOperation = "audit_checkpoint"
	AuditKeyLifecycle          AuditOperation = "audit_key_lifecycle"
	AuditStagingAuthentication AuditOperation = "staging_authentication"
	AuditStagingAuthorization  AuditOperation = "staging_authorization"
	AuditStagingLifecycle      AuditOperation = "staging_lifecycle"
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
	AuditReasonRevoked                 AuditReason = "revoked"
	AuditReasonRefreshed               AuditReason = "refreshed"
	AuditReasonRestoreVerified         AuditReason = "restore_verified"
	AuditReasonCheckpointCommitted     AuditReason = "checkpoint_committed"
	AuditReasonKeyLifecycleCommitted   AuditReason = "key_lifecycle_committed"
	AuditReasonOperationUnavailable    AuditReason = "operation_unavailable"
	AuditReasonAccessDenied            AuditReason = "access_denied"
	AuditReasonDependencyUnavailable   AuditReason = "dependency_unavailable"
	AuditReasonCredentialExpired       AuditReason = "credential_expired"
	AuditReasonRegistrationLoaded      AuditReason = "registration_loaded"
	AuditReasonTLSReady                AuditReason = "tls_ready"
	AuditReasonStarted                 AuditReason = "started"
	AuditReasonStopped                 AuditReason = "stopped"
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
	AuthorityReference    string
	JWKSSetDigest         [sha256.Size]byte
	HasJWKSSetDigest      bool
	CheckpointReference   string
	SigningKeyReference   string
	RecoveryReference     string
	ServiceProfile        string
	Action                string
	IdentityReference     string
}

type Auditor interface {
	Record(context.Context, AuditRecord) (receipt string, err error)
	Ready(context.Context) error
}
