package primitivesstaging

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func OpenAuditLedger(config *Config) (*auditsqlite.Ledger, error) {
	if config == nil || config.ValidatePaths() != nil {
		return nil, ErrInvalid
	}
	ledger, err := auditsqlite.Open(config.AuditDatabasePath())
	if err != nil {
		return nil, ErrUnavailable
	}
	return ledger, nil
}

type AuditGate struct {
	authenticator primitivesauth.Authenticator
	actions       primitivesauth.ActionAuthorizer
	scopes        primitivesauth.ScopeAuthorizer
	auditor       identity.Auditor
	now           func() time.Time
	failed        atomic.Bool
}

type credentialExpiry interface {
	CredentialExpired() bool
}

func NewAuditGate(ctx context.Context, authenticator primitivesauth.Authenticator, actions primitivesauth.ActionAuthorizer, scopes primitivesauth.ScopeAuthorizer, auditor identity.Auditor, now func() time.Time) (*AuditGate, error) {
	if ctx == nil || authenticator == nil || actions == nil || scopes == nil || auditor == nil || now == nil {
		return nil, ErrInvalid
	}
	gate := &AuditGate{authenticator: authenticator, actions: actions, scopes: scopes, auditor: auditor, now: now}
	if err := gate.record(ctx, identity.AuditStagingLifecycle, identity.AuditAllow, identity.AuditReasonRegistrationLoaded, "", primitivesauth.Action("")); err != nil {
		return nil, ErrUnavailable
	}
	return gate, nil
}

func (g *AuditGate) Authenticate(ctx context.Context, material primitivesauth.RequestAuthentication) (primitivesauth.Identity, error) {
	if g == nil {
		return primitivesauth.Identity{}, primitivesauth.ErrTemporarilyUnavailable
	}
	result, innerErr := g.authenticator.Authenticate(ctx, material)
	outcome, reason := identity.AuditAllow, identity.AuditReasonAllowed
	if errors.Is(innerErr, primitivesauth.ErrUnauthenticated) {
		outcome, reason = identity.AuditDeny, identity.AuditReasonInvalidCredential
	} else if innerErr != nil {
		outcome, reason = identity.AuditUnavailable, identity.AuditReasonDependencyUnavailable
	}
	identityReference := ""
	if innerErr == nil {
		identityReference = referenceForIdentity(result)
	}
	if err := g.record(ctx, identity.AuditStagingAuthentication, outcome, reason, identityReference, ""); err != nil {
		return primitivesauth.Identity{}, primitivesauth.ErrTemporarilyUnavailable
	}
	return result, innerErr
}

func (g *AuditGate) AuthorizeAction(ctx context.Context, subject primitivesauth.Identity, action primitivesauth.Action) error {
	if g == nil {
		return primitivesauth.ErrTemporarilyUnavailable
	}
	return g.authorize(ctx, subject, action, func() error { return g.actions.AuthorizeAction(ctx, subject, action) })
}

func (g *AuditGate) AuthorizeScope(ctx context.Context, subject primitivesauth.Identity, action primitivesauth.Action, scope coordination.Digest) error {
	if g == nil {
		return primitivesauth.ErrTemporarilyUnavailable
	}
	return g.authorize(ctx, subject, action, func() error { return g.scopes.AuthorizeScope(ctx, subject, action, scope) })
}

func (g *AuditGate) authorize(ctx context.Context, subject primitivesauth.Identity, action primitivesauth.Action, operation func() error) error {
	innerErr := operation()
	outcome, reason := identity.AuditAllow, identity.AuditReasonAllowed
	if errors.Is(innerErr, primitivesauth.ErrAccessDenied) {
		outcome, reason = identity.AuditDeny, identity.AuditReasonAccessDenied
	} else if innerErr != nil {
		outcome, reason = identity.AuditUnavailable, identity.AuditReasonDependencyUnavailable
	}
	if err := g.record(ctx, identity.AuditStagingAuthorization, outcome, reason, referenceForIdentity(subject), action); err != nil {
		return primitivesauth.ErrTemporarilyUnavailable
	}
	return innerErr
}

func (g *AuditGate) RecordLifecycle(ctx context.Context, reason identity.AuditReason) error {
	if reason != identity.AuditReasonTLSReady && reason != identity.AuditReasonStarted && reason != identity.AuditReasonStopped {
		return ErrInvalid
	}
	return g.record(ctx, identity.AuditStagingLifecycle, identity.AuditAllow, reason, "", "")
}

func (g *AuditGate) RecordDependencyUnavailable(ctx context.Context) error {
	if status, ok := g.authenticator.(credentialExpiry); ok && status.CredentialExpired() {
		return g.record(ctx, identity.AuditStagingAuthentication, identity.AuditDeny, identity.AuditReasonCredentialExpired, "", "")
	}
	return g.record(ctx, identity.AuditStagingLifecycle, identity.AuditUnavailable, identity.AuditReasonDependencyUnavailable, "", "")
}

func (g *AuditGate) RecordCapabilityKeyLifecycle(ctx context.Context, loaded bool) error {
	reason := identity.AuditReasonCapabilityKeyZeroed
	if loaded {
		reason = identity.AuditReasonCapabilityKeyLoaded
	}
	return g.record(ctx, identity.AuditStagingLifecycle, identity.AuditAllow, reason, "", "")
}

func (g *AuditGate) RecordStorageEpochValidated(ctx context.Context) error {
	return g.record(ctx, identity.AuditStagingLifecycle, identity.AuditAllow, identity.AuditReasonStorageEpochValidated, "", "")
}

func (g *AuditGate) Ready() bool {
	return g != nil && !g.failed.Load() && g.auditor != nil && g.auditor.Ready(context.Background()) == nil
}

func (g *AuditGate) record(ctx context.Context, operation identity.AuditOperation, outcome identity.AuditOutcome, reason identity.AuditReason, identityReference string, action primitivesauth.Action) error {
	if g == nil || g.failed.Load() {
		return ErrUnavailable
	}
	operationID, err := uuid.NewV7()
	if err != nil {
		g.failed.Store(true)
		return ErrUnavailable
	}
	decisionTime := g.now().UTC().Truncate(time.Millisecond)
	if !validMillisecond(decisionTime) {
		g.failed.Store(true)
		return ErrUnavailable
	}
	record := identity.AuditRecord{
		ProfileVersion: 1, OperationID: operationID.String(), Operation: operation,
		Outcome: outcome, Reason: reason, DecisionTime: decisionTime,
		ServiceProfile: Profile, Action: string(action), IdentityReference: identityReference,
	}
	if _, err := g.auditor.Record(ctx, record); err != nil {
		g.failed.Store(true)
		return ErrUnavailable
	}
	return nil
}

func referenceForIdentity(value primitivesauth.Identity) string {
	if value.Tenant() == "" || value.Principal() == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("yukh-coordination:staging-audit-identity:v1\n" + value.Tenant() + "\n" + value.Principal()))
	return "staging-identity:" + base64.RawURLEncoding.EncodeToString(digest[:])
}
