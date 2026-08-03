package primitivesstaging

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
	"github.com/nomed/yukh-coordination/internal/relay/audit"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
	_ "modernc.org/sqlite"
)

type auditFixture struct {
	identity  primitivesauth.Identity
	authErr   error
	actionErr error
	scopeErr  error
	expired   bool
}

func (fixture *auditFixture) Authenticate(context.Context, primitivesauth.RequestAuthentication) (primitivesauth.Identity, error) {
	return fixture.identity, fixture.authErr
}
func (fixture *auditFixture) AuthorizeAction(context.Context, primitivesauth.Identity, primitivesauth.Action) error {
	return fixture.actionErr
}
func (fixture *auditFixture) AuthorizeScope(context.Context, primitivesauth.Identity, primitivesauth.Action, coordination.Digest) error {
	return fixture.scopeErr
}
func (fixture *auditFixture) CredentialExpired() bool { return fixture.expired }

type unavailableAuditor struct{}

func (*unavailableAuditor) Record(context.Context, identity.AuditRecord) (string, error) {
	return "", audit.ErrUnavailable
}
func (*unavailableAuditor) Ready(context.Context) error { return nil }

func TestAuditGatePersistsClosedRedactedDecisionsAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 3, 18, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.db")
	ledger, err := auditsqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := primitivesauth.NewIdentity("tenant-secret", "principal-secret")
	fixture := &auditFixture{identity: subject}
	gate, err := NewAuditGate(context.Background(), fixture, fixture, fixture, ledger, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	material, _ := primitivesauth.NewRequestAuthentication("token-secret", "proof.secret.value", "POST", "https://private.invalid/secret-path")
	admitted, err := gate.Authenticate(context.Background(), material)
	if err != nil || admitted.Tenant() != subject.Tenant() {
		t.Fatalf("authenticate = %#v, %v", admitted, err)
	}
	if err := gate.AuthorizeAction(context.Background(), subject, primitivesauth.LeaseAcquire); err != nil {
		t.Fatal(err)
	}
	scope := coordination.Digest(strings.Repeat("a", 64))
	if err := gate.AuthorizeScope(context.Background(), subject, primitivesauth.LeaseAcquire, scope); err != nil {
		t.Fatal(err)
	}
	if err := gate.RecordCapabilityKeyLifecycle(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := gate.RecordCapabilityKeyLifecycle(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := gate.RecordStorageEpochValidated(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := auditsqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT canonical_record FROM audit_entries ORDER BY sequence")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var records []string
	for rows.Next() {
		var record string
		if err := rows.Scan(&record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if len(records) != 7 {
		t.Fatalf("record count = %d", len(records))
	}
	joined := strings.Join(records, "\n")
	for _, prohibited := range []string{"token-secret", "proof.secret.value", "tenant-secret", "principal-secret", string(scope), "private.invalid", "secret-path"} {
		if strings.Contains(joined, prohibited) {
			t.Fatalf("audit contains prohibited value %q", prohibited)
		}
	}
	for _, required := range []string{`"operation_kind":"staging_lifecycle"`, `"operation_kind":"staging_authentication"`, `"operation_kind":"staging_authorization"`, `"action":"coordination.lease.acquire"`, `"identity_reference":"staging-identity:`, `"reason":"capability_key_loaded"`, `"reason":"capability_key_zeroed"`, `"reason":"storage_epoch_validated"`} {
		if !strings.Contains(joined, required) {
			t.Fatalf("audit missing %s", required)
		}
	}
}

func TestAuditGateFailsClosedWhenAppendFails(t *testing.T) {
	now := time.Date(2026, 8, 3, 18, 30, 0, 0, time.UTC)
	subject, _ := primitivesauth.NewIdentity("tenant-a", "principal-a")
	fixture := &auditFixture{identity: subject}
	gate := &AuditGate{authenticator: fixture, actions: fixture, scopes: fixture, auditor: &unavailableAuditor{}, now: func() time.Time { return now }}
	material, _ := primitivesauth.NewRequestAuthentication("token", "proof.value.value", "POST", "https://private.invalid/path")
	if _, err := gate.Authenticate(context.Background(), material); !errors.Is(err, primitivesauth.ErrTemporarilyUnavailable) {
		t.Fatalf("authentication append failure = %v", err)
	}
	if gate.Ready() {
		t.Fatal("audit gate remained ready after uncertain append")
	}
	fixture.actionErr = primitivesauth.ErrAccessDenied
	if err := gate.AuthorizeAction(context.Background(), subject, primitivesauth.LeaseAcquire); !errors.Is(err, primitivesauth.ErrTemporarilyUnavailable) {
		t.Fatalf("authorization append failure = %v", err)
	}
}

func TestAuditGateRecordsCredentialExpiryAsClosedDenial(t *testing.T) {
	now := time.Date(2026, 8, 3, 18, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.db")
	ledger, err := auditsqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &auditFixture{}
	gate, err := NewAuditGate(context.Background(), fixture, fixture, fixture, ledger, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture.expired = true
	if err := gate.RecordDependencyUnavailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var canonical string
	if err := db.QueryRow("SELECT canonical_record FROM audit_entries ORDER BY sequence DESC LIMIT 1").Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"operation_kind":"staging_authentication"`, `"outcome":"deny"`, `"reason":"credential_expired"`} {
		if !strings.Contains(canonical, required) {
			t.Fatalf("expiry audit missing %s: %s", required, canonical)
		}
	}
}

func TestStagingAuditFieldsCannotEnterLegacyRecord(t *testing.T) {
	record := identity.AuditRecord{
		ProfileVersion: 1, OperationID: "0198f76a-4c00-7000-8000-000000000001",
		Operation: identity.AuditJWKSRefresh, Outcome: identity.AuditUnavailable,
		Reason: identity.AuditReasonDependencyUnavailable, DecisionTime: time.Date(2026, 8, 3, 18, 30, 0, 0, time.UTC),
		AuthorityReference: "authority:fixture", ServiceProfile: Profile,
	}
	if _, err := audit.CanonicalRecord(record); !errors.Is(err, audit.ErrInvalidRecord) {
		t.Fatalf("legacy staging-field smuggling error = %v", err)
	}
}
