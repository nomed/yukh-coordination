package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const (
	providerProfileVersion = 1
	maxSessionLifetime     = 15 * time.Minute
	maxGenerationAttempts  = 3
	maxSafeSessionEpoch    = uint64(9_007_199_254_740_991)
)

type Registry interface {
	ReserveBootstrap(context.Context, BootstrapReservation) (PendingSession, error)
	ActivateBootstrap(context.Context, string, string) (ActiveSession, error)
	Authenticate(context.Context, AuthenticationReservation) (ActiveSession, error)
	Status(context.Context) (RegistryStatus, error)
}

type TokenVerifier interface {
	VerifyBootstrap(context.Context, string, string, string, string) (BootstrapIdentity, error)
	VerifySessionProof(string, string, string, string) (Proof, error)
	Ready() bool
}

type Provider struct {
	verifier TokenVerifier
	registry Registry
	auditor  Auditor
	random   io.Reader
	now      func() time.Time
	newID    func() (uuid.UUID, error)
}

var (
	_ httpapi.SessionBootstrapper = (*Provider)(nil)
	_ httpapi.Authenticator       = (*Provider)(nil)
)

func NewProvider(verifier TokenVerifier, registry Registry, auditor Auditor) (*Provider, error) {
	return newProvider(verifier, registry, auditor, rand.Reader, time.Now, uuid.NewV7)
}

func newProvider(verifier TokenVerifier, registry Registry, auditor Auditor, random io.Reader, now func() time.Time, newID func() (uuid.UUID, error)) (*Provider, error) {
	if nilDependency(verifier) || nilDependency(registry) || nilDependency(auditor) || random == nil || now == nil || newID == nil {
		return nil, httpapi.ErrAuthenticationUnavailable
	}
	return &Provider{verifier: verifier, registry: registry, auditor: auditor, random: random, now: now, newID: newID}, nil
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func (p *Provider) Bootstrap(ctx context.Context, material httpapi.BootstrapAuthentication) (httpapi.IssuedSession, error) {
	if p == nil || ctx == nil {
		return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
	}
	attemptID, err := p.nextID()
	if err != nil {
		return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
	}
	external, err := p.verifier.VerifyBootstrap(ctx, material.Credential(), material.Proof(), material.Method(), material.TargetURI())
	if err != nil {
		return httpapi.IssuedSession{}, p.auditFailure(ctx, attemptID, AuditBootstrap, classifyVerification(err), nil, nil)
	}
	issuedAt := p.now().UTC().Truncate(time.Millisecond)
	expiresAt := issuedAt.Add(maxSessionLifetime)
	if external.TokenExpiresAt.Before(expiresAt) {
		expiresAt = external.TokenExpiresAt.UTC().Truncate(time.Millisecond)
	}
	if !expiresAt.After(issuedAt) {
		return httpapi.IssuedSession{}, p.auditFailure(ctx, attemptID, AuditBootstrap, failure{AuditUnavailable, AuditReasonVerificationUnavailable, httpapi.ErrAuthenticationUnavailable}, &external, nil)
	}

	for range maxGenerationAttempts {
		token, digest, participantID, operationID, generationErr := p.generateSessionMaterial()
		if generationErr != nil {
			return httpapi.IssuedSession{}, p.auditFailure(ctx, attemptID, AuditBootstrap, failure{AuditUnavailable, AuditReasonRegistryUnavailable, httpapi.ErrAuthenticationUnavailable}, &external, nil)
		}
		pending, reserveErr := p.registry.ReserveBootstrap(ctx, BootstrapReservation{
			Session: PendingSession{
				TenantID: external.TenantID, PrincipalID: external.PrincipalID, ParticipantInstanceID: participantID,
				TokenDigest: digest, DPoPThumbprint: external.DPoPThumbprint, IssuedAt: issuedAt, ExpiresAt: expiresAt,
				BootstrapOperationID: operationID,
			},
			ProofJTI: external.ProofJTI, ProofIAT: external.ProofIssuedAt,
		})
		if errors.Is(reserveErr, ErrSessionConflict) {
			collisionID, idErr := p.nextID()
			if idErr != nil || p.recordFailure(ctx, collisionID, AuditBootstrap, failure{AuditUnavailable, AuditReasonMaterialCollision, httpapi.ErrAuthenticationUnavailable}, &external, nil) != nil {
				return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
			}
			continue
		}
		if reserveErr != nil {
			return httpapi.IssuedSession{}, p.auditFailure(ctx, operationID, AuditBootstrap, classifyRegistry(reserveErr), &external, nil)
		}
		record := auditRecord(operationID, AuditBootstrap, AuditAllow, AuditReasonAllowed, issuedAt, &external.DPoPThumbprint)
		record.TenantID = pending.TenantID
		record.PrincipalID = pending.PrincipalID
		record.ParticipantInstanceID = pending.ParticipantInstanceID
		record.SessionEpoch = pending.SessionEpoch
		receipt, auditErr := p.recordAudit(ctx, record)
		if auditErr != nil {
			return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
		}
		if _, activationErr := p.registry.ActivateBootstrap(ctx, operationID, receipt); activationErr != nil {
			return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
		}
		return httpapi.IssuedSession{
			SessionToken: token, ParticipantInstanceID: pending.ParticipantInstanceID, SessionEpoch: pending.SessionEpoch,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}, nil
	}
	return httpapi.IssuedSession{}, p.auditFailure(ctx, attemptID, AuditBootstrap, failure{AuditUnavailable, AuditReasonRegistryUnavailable, httpapi.ErrAuthenticationUnavailable}, &external, nil)
}

func (p *Provider) Authenticate(ctx context.Context, material httpapi.SessionAuthentication) (httpapi.Identity, error) {
	if p == nil || ctx == nil {
		return httpapi.Identity{}, httpapi.ErrAuthenticationUnavailable
	}
	operationID, err := p.nextID()
	if err != nil {
		return httpapi.Identity{}, httpapi.ErrAuthenticationUnavailable
	}
	proof, err := p.verifier.VerifySessionProof(material.Proof(), material.Credential(), material.Method(), material.TargetURI())
	if err != nil {
		return httpapi.Identity{}, p.auditFailure(ctx, operationID, AuditAuthentication, classifyVerification(err), nil, nil)
	}
	digest := sessionTokenDigest(material.Credential())
	active, err := p.registry.Authenticate(ctx, AuthenticationReservation{
		TokenDigest: digest, DPoPThumbprint: proof.JWKThumbprint, ProofJTI: proof.JTI, ProofIAT: proof.IssuedAt,
	})
	if err != nil {
		return httpapi.Identity{}, p.auditFailure(ctx, operationID, AuditAuthentication, classifyRegistry(err), nil, &proof)
	}
	record := auditRecord(operationID, AuditAuthentication, AuditAllow, AuditReasonAllowed, p.now().UTC().Truncate(time.Millisecond), &proof.JWKThumbprint)
	record.TenantID = active.TenantID
	record.PrincipalID = active.PrincipalID
	record.ParticipantInstanceID = active.ParticipantInstanceID
	record.SessionEpoch = active.SessionEpoch
	if _, err := p.recordAudit(ctx, record); err != nil {
		return httpapi.Identity{}, httpapi.ErrAuthenticationUnavailable
	}
	return httpapi.Identity{
		TenantID: active.TenantID, PrincipalID: active.PrincipalID,
		ParticipantInstanceID: active.ParticipantInstanceID, SessionEpoch: active.SessionEpoch,
	}, nil
}

func (p *Provider) Ready(ctx context.Context) error {
	if p == nil || ctx == nil || !p.verifier.Ready() {
		return httpapi.ErrAuthenticationUnavailable
	}
	status, err := p.registry.Status(ctx)
	if err != nil || status.FenceState != "admitted" {
		return httpapi.ErrAuthenticationUnavailable
	}
	if err := p.auditor.Ready(ctx); err != nil {
		return httpapi.ErrAuthenticationUnavailable
	}
	return nil
}

func (p *Provider) generateSessionMaterial() (string, [sha256.Size]byte, string, string, error) {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(p.random, secret); err != nil {
		return "", [sha256.Size]byte{}, "", "", err
	}
	participantID, err := p.nextID()
	if err != nil {
		return "", [sha256.Size]byte{}, "", "", err
	}
	operationID, err := p.nextID()
	if err != nil {
		return "", [sha256.Size]byte{}, "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	return token, sessionTokenDigest(token), participantID, operationID, nil
}

func (p *Provider) nextID() (string, error) {
	value, err := p.newID()
	if err != nil || value.Version() != 7 {
		return "", httpapi.ErrAuthenticationUnavailable
	}
	return value.String(), nil
}

type failure struct {
	outcome AuditOutcome
	reason  AuditReason
	public  error
}

func classifyVerification(err error) failure {
	if errors.Is(err, errInvalid) {
		return failure{AuditDeny, AuditReasonInvalidCredential, httpapi.ErrUnauthenticated}
	}
	if errors.Is(err, errUnavailable) {
		return failure{AuditUnavailable, AuditReasonVerificationUnavailable, httpapi.ErrAuthenticationUnavailable}
	}
	return failure{AuditUnavailable, AuditReasonVerificationUnavailable, httpapi.ErrAuthenticationUnavailable}
}

func classifyRegistry(err error) failure {
	switch {
	case errors.Is(err, ErrProofReplay):
		return failure{AuditDeny, AuditReasonProofReplay, httpapi.ErrUnauthenticated}
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionConflict):
		return failure{AuditDeny, AuditReasonInactiveSession, httpapi.ErrUnauthenticated}
	default:
		return failure{AuditUnavailable, AuditReasonRegistryUnavailable, httpapi.ErrAuthenticationUnavailable}
	}
}

func (p *Provider) auditFailure(ctx context.Context, operationID string, operation AuditOperation, result failure, external *BootstrapIdentity, proof *Proof) error {
	if err := p.recordFailure(ctx, operationID, operation, result, external, proof); err != nil {
		return httpapi.ErrAuthenticationUnavailable
	}
	return result.public
}

func (p *Provider) recordFailure(ctx context.Context, operationID string, operation AuditOperation, result failure, external *BootstrapIdentity, proof *Proof) error {
	var thumbprint *[sha256.Size]byte
	if external != nil {
		thumbprint = &external.DPoPThumbprint
	} else if proof != nil {
		thumbprint = &proof.JWKThumbprint
	}
	record := auditRecord(operationID, operation, result.outcome, result.reason, p.now().UTC().Truncate(time.Millisecond), thumbprint)
	if external != nil {
		record.TenantID = external.TenantID
		record.PrincipalID = external.PrincipalID
	}
	if _, err := p.recordAudit(ctx, record); err != nil {
		return err
	}
	return nil
}

func (p *Provider) recordAudit(ctx context.Context, record AuditRecord) (string, error) {
	if !validAuditRecord(record) {
		return "", httpapi.ErrAuthenticationUnavailable
	}
	return p.auditor.Record(ctx, record)
}

func validAuditRecord(record AuditRecord) bool {
	operationID, err := uuid.Parse(record.OperationID)
	if err != nil || operationID.Version() != 7 || operationID.String() != record.OperationID || record.ProfileVersion != providerProfileVersion || record.DecisionTime.Location() != time.UTC || !record.DecisionTime.Equal(record.DecisionTime.Truncate(time.Millisecond)) {
		return false
	}
	if record.Operation != AuditBootstrap && record.Operation != AuditAuthentication {
		return false
	}
	switch record.Outcome {
	case AuditAllow:
		if record.Reason != AuditReasonAllowed || !validTenantAuditIdentity(record, true) || !record.HasDPoPThumbprint {
			return false
		}
	case AuditDeny:
		if record.Reason != AuditReasonInvalidCredential && record.Reason != AuditReasonProofReplay && record.Reason != AuditReasonInactiveSession {
			return false
		}
		if !validTenantAuditIdentity(record, false) {
			return false
		}
	case AuditUnavailable:
		if record.Reason != AuditReasonVerificationUnavailable && record.Reason != AuditReasonRegistryUnavailable && record.Reason != AuditReasonMaterialCollision {
			return false
		}
		if !validTenantAuditIdentity(record, false) {
			return false
		}
	default:
		return false
	}
	return record.HasDPoPThumbprint || record.DPoPThumbprint == ([sha256.Size]byte{})
}

func validTenantAuditIdentity(record AuditRecord, required bool) bool {
	hasTenant := record.TenantID != "" || record.PrincipalID != ""
	if hasTenant && (!tenantPattern.MatchString(record.TenantID) || !validAuditDigest(record.PrincipalID)) {
		return false
	}
	hasSession := record.ParticipantInstanceID != "" || record.SessionEpoch != 0
	if hasSession {
		participant, err := uuid.Parse(record.ParticipantInstanceID)
		if err != nil || participant.Version() != 7 || participant.String() != record.ParticipantInstanceID || record.SessionEpoch == 0 || record.SessionEpoch > maxSafeSessionEpoch || !hasTenant {
			return false
		}
	}
	return !required || (hasTenant && hasSession)
}

func validAuditDigest(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func auditRecord(operationID string, operation AuditOperation, outcome AuditOutcome, reason AuditReason, at time.Time, thumbprint *[sha256.Size]byte) AuditRecord {
	record := AuditRecord{
		ProfileVersion: providerProfileVersion, OperationID: operationID, Operation: operation,
		Outcome: outcome, Reason: reason, DecisionTime: at,
	}
	if thumbprint != nil {
		record.DPoPThumbprint = *thumbprint
		record.HasDPoPThumbprint = true
	}
	return record
}

func sessionTokenDigest(token string) [sha256.Size]byte {
	preimage := make([]byte, 0, len(token)+48)
	preimage = append(preimage, "yukh-coordination:session-token:v1\n"...)
	preimage = append(preimage, token...)
	return sha256.Sum256(preimage)
}
