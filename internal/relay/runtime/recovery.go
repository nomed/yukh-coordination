package runtime

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

type RestoreIdentity interface {
	StageRestoreFloors(context.Context, string, string, time.Time, []identity.EpochFloor) error
	CompleteRestore(context.Context, string, string, string) error
}

type restoreAudit interface {
	ValidateRestore(context.Context, audit.SignedRecoveryManifest, ed25519.PublicKey) (*auditsqlite.RestorePlan, error)
	AcceptedRestore(context.Context, *auditsqlite.RestorePlan) (string, bool, error)
	CommitRestore(context.Context, *auditsqlite.RestorePlan, string, time.Time) (string, error)
}

// RestoreCoordinator owns the explicit cross-database recovery saga. It does
// not claim atomicity across SQLite files: every transition is monotonic,
// fenced and safe to repeat after a crash.
type RestoreCoordinator struct {
	audit    restoreAudit
	identity RestoreIdentity
}

func NewRestoreCoordinator(ledger restoreAudit, registry RestoreIdentity) (*RestoreCoordinator, error) {
	if isNil(ledger) || isNil(registry) {
		return nil, audit.ErrUnavailable
	}
	return &RestoreCoordinator{audit: ledger, identity: registry}, nil
}

func (c *RestoreCoordinator) Recover(ctx context.Context, signed audit.SignedRecoveryManifest, authority ed25519.PublicKey, operationID string, at time.Time) (string, error) {
	if c == nil || ctx == nil {
		return "", audit.ErrUnavailable
	}
	plan, err := c.audit.ValidateRestore(ctx, signed, authority)
	if err != nil {
		return "", err
	}
	if receipt, accepted, err := c.audit.AcceptedRestore(ctx, plan); err != nil {
		return "", err
	} else if accepted {
		if err := c.identity.CompleteRestore(ctx, plan.IdentityDatabaseID(), plan.ManifestReference(), receipt); err != nil {
			return "", audit.ErrUnavailable
		}
		return receipt, nil
	}
	if err := c.identity.StageRestoreFloors(ctx, plan.IdentityDatabaseID(), plan.ManifestReference(), plan.IdentityWallHighWater(), plan.EpochFloors()); err != nil {
		return "", audit.ErrUnavailable
	}
	receipt, err := c.audit.CommitRestore(ctx, plan, operationID, at)
	if err != nil {
		return "", err
	}
	if err := c.identity.CompleteRestore(ctx, plan.IdentityDatabaseID(), plan.ManifestReference(), receipt); err != nil {
		return "", audit.ErrUnavailable
	}
	return receipt, nil
}
