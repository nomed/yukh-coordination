package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

func TestRestoreCoordinatorOrdersAndResumesSaga(t *testing.T) {
	log := []string{}
	auditPort := &fakeRestoreAudit{log: &log, plan: &auditsqlite.RestorePlan{}, receipt: "audit:ledger:1:receipt"}
	identityPort := &fakeRestoreIdentity{log: &log}
	coordinator, err := NewRestoreCoordinator(auditPort, identityPort)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := coordinator.Recover(context.Background(), audit.SignedRecoveryManifest{}, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), "0198f56b-0c00-7000-8000-000000000001", time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)); err != nil || receipt != auditPort.receipt {
		t.Fatalf("recover = %q, %v", receipt, err)
	}
	if got := strings.Join(log, ","); got != "validate,accepted,stage,commit,complete" {
		t.Fatalf("order = %s", got)
	}
	log = nil
	auditPort.accepted = true
	if _, err := coordinator.Recover(context.Background(), audit.SignedRecoveryManifest{}, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), "0198f56b-0c00-7000-8000-000000000002", time.Date(2026, 8, 3, 10, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, ","); got != "validate,accepted,complete" {
		t.Fatalf("resume order = %s", got)
	}
}

func TestRestoreCoordinatorDoesNotCommitBeforeFloors(t *testing.T) {
	log := []string{}
	auditPort := &fakeRestoreAudit{log: &log, plan: &auditsqlite.RestorePlan{}, receipt: "audit:ledger:1:receipt"}
	identityPort := &fakeRestoreIdentity{log: &log, stageErr: errors.New("identity unavailable")}
	coordinator, _ := NewRestoreCoordinator(auditPort, identityPort)
	if _, err := coordinator.Recover(context.Background(), audit.SignedRecoveryManifest{}, make(ed25519.PublicKey, ed25519.PublicKeySize), "0198f56b-0c00-7000-8000-000000000001", time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC)); !errors.Is(err, audit.ErrUnavailable) {
		t.Fatalf("recover = %v", err)
	}
	if got := strings.Join(log, ","); got != "validate,accepted,stage" {
		t.Fatalf("failure order = %s", got)
	}
}

type fakeRestoreAudit struct {
	log      *[]string
	plan     *auditsqlite.RestorePlan
	receipt  string
	accepted bool
}

func (f *fakeRestoreAudit) ValidateRestore(context.Context, audit.SignedRecoveryManifest, ed25519.PublicKey) (*auditsqlite.RestorePlan, error) {
	*f.log = append(*f.log, "validate")
	return f.plan, nil
}
func (f *fakeRestoreAudit) AcceptedRestore(context.Context, *auditsqlite.RestorePlan) (string, bool, error) {
	*f.log = append(*f.log, "accepted")
	return f.receipt, f.accepted, nil
}
func (f *fakeRestoreAudit) CommitRestore(context.Context, *auditsqlite.RestorePlan, string, time.Time) (string, error) {
	*f.log = append(*f.log, "commit")
	return f.receipt, nil
}

type fakeRestoreIdentity struct {
	log      *[]string
	stageErr error
}

func (f *fakeRestoreIdentity) StageRestoreFloors(context.Context, string, string, time.Time, []identity.EpochFloor) error {
	*f.log = append(*f.log, "stage")
	return f.stageErr
}
func (f *fakeRestoreIdentity) CompleteRestore(context.Context, string, string, string) error {
	*f.log = append(*f.log, "complete")
	return nil
}
