package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
)

const (
	providerPublicBase = "https://public.coord.example"
	providerTarget     = providerPublicBase + "/coordination/v1/channels/channel:test/transcripts/1/records"
	providerProof      = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJ0ZXN0In0.c2lnbmF0dXJl"
)

type fakeTokenVerifier struct {
	bootstrap    BootstrapIdentity
	proof        Proof
	bootstrapErr error
	proofErr     error
	ready        bool
	bootstrapN   int
	proofN       int
}

func (v *fakeTokenVerifier) VerifyBootstrap(context.Context, string, string, string, string) (BootstrapIdentity, error) {
	v.bootstrapN++
	return v.bootstrap, v.bootstrapErr
}

func (v *fakeTokenVerifier) VerifySessionProof(string, string, string, string) (Proof, error) {
	v.proofN++
	return v.proof, v.proofErr
}

func (v *fakeTokenVerifier) Ready() bool { return v.ready }

type fakeRegistry struct {
	mu              sync.Mutex
	order           *[]string
	pending         PendingSession
	active          ActiveSession
	reserveErr      error
	activateErr     error
	authenticateErr error
	reserveCalls    int
	activateCalls   int
	authCalls       int
	lastBootstrap   BootstrapReservation
	lastAuth        AuthenticationReservation
	seenProofs      map[string]struct{}
	status          RegistryStatus
}

func (r *fakeRegistry) ReserveBootstrap(_ context.Context, request BootstrapReservation) (PendingSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reserveCalls++
	r.lastBootstrap = request
	r.appendOrder("reserve")
	if r.reserveErr != nil {
		return PendingSession{}, r.reserveErr
	}
	request.Session.SessionEpoch = 7
	r.pending = request.Session
	return request.Session, nil
}

func (r *fakeRegistry) ActivateBootstrap(_ context.Context, operationID, receipt string) (ActiveSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activateCalls++
	r.appendOrder("activate")
	if r.activateErr != nil || operationID != r.pending.BootstrapOperationID || receipt != "audit:receipt:1" {
		if r.activateErr != nil {
			return ActiveSession{}, r.activateErr
		}
		return ActiveSession{}, ErrSessionConflict
	}
	r.active = ActiveSession{
		TenantID: r.pending.TenantID, PrincipalID: r.pending.PrincipalID,
		ParticipantInstanceID: r.pending.ParticipantInstanceID, SessionEpoch: r.pending.SessionEpoch,
		DPoPThumbprint: r.pending.DPoPThumbprint, ExpiresAt: r.pending.ExpiresAt,
	}
	return r.active, nil
}

func (r *fakeRegistry) Authenticate(_ context.Context, request AuthenticationReservation) (ActiveSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authCalls++
	r.lastAuth = request
	r.appendOrder("authenticate")
	if r.authenticateErr != nil {
		return ActiveSession{}, r.authenticateErr
	}
	if r.seenProofs == nil {
		r.seenProofs = make(map[string]struct{})
	}
	if _, exists := r.seenProofs[request.ProofJTI]; exists {
		return ActiveSession{}, ErrProofReplay
	}
	r.seenProofs[request.ProofJTI] = struct{}{}
	return r.active, nil
}

func (r *fakeRegistry) Status(context.Context) (RegistryStatus, error) { return r.status, nil }

func (r *fakeRegistry) appendOrder(value string) {
	if r.order != nil {
		*r.order = append(*r.order, value)
	}
}

type fakeAuditor struct {
	mu      sync.Mutex
	order   *[]string
	records []AuditRecord
	err     error
	ready   error
}

func (a *fakeAuditor) Record(_ context.Context, record AuditRecord) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, record)
	if a.order != nil {
		*a.order = append(*a.order, "audit")
	}
	if a.err != nil {
		return "", a.err
	}
	return "audit:receipt:1", nil
}

func (a *fakeAuditor) Ready(context.Context) error { return a.ready }

func TestProviderBootstrapOrdersPendingAuditAndActivation(t *testing.T) {
	provider, verifier, registry, auditor, now := providerFixture(t)
	handler := providerHandler(t, provider)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, bootstrapHTTPRequest())
	if response.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", response.Code, response.Body.String())
	}
	if got := *registry.order; len(got) != 3 || got[0] != "reserve" || got[1] != "audit" || got[2] != "activate" {
		t.Fatalf("bootstrap order: %v", got)
	}
	var body struct {
		SessionToken string `json:"session_token"`
		Epoch        uint64 `json:"session_epoch"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.SessionToken) != 43 || body.Epoch != 7 || verifier.bootstrapN != 1 || registry.activateCalls != 1 {
		t.Fatalf("unexpected bootstrap result: %#v", body)
	}
	if registry.lastBootstrap.Session.TokenDigest != sessionTokenDigest(body.SessionToken) || registry.lastBootstrap.Session.IssuedAt != now || registry.lastBootstrap.Session.ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("wrong pending reservation: %#v", registry.lastBootstrap)
	}
	if len(auditor.records) != 1 || auditor.records[0].Outcome != AuditAllow || auditor.records[0].ParticipantInstanceID == "" || auditor.records[0].SessionEpoch != 7 {
		t.Fatalf("wrong allow audit: %#v", auditor.records)
	}
}

func TestProviderBootstrapAuditOutageDisclosesNoToken(t *testing.T) {
	provider, _, registry, auditor, _ := providerFixture(t)
	auditor.err = errors.New("audit offline with secret text")
	response := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(response, bootstrapHTTPRequest())
	if response.Code != http.StatusServiceUnavailable || bytes.Contains(response.Body.Bytes(), []byte("secret text")) || registry.activateCalls != 0 {
		t.Fatalf("audit outage leaked or activated: %d %s activate=%d", response.Code, response.Body.String(), registry.activateCalls)
	}
}

func TestProviderBoundsMaterialCollisionAndActivationUncertainty(t *testing.T) {
	provider, _, registry, auditor, _ := providerFixture(t)
	registry.reserveErr = ErrSessionConflict
	collisions := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(collisions, bootstrapHTTPRequest())
	if collisions.Code != http.StatusServiceUnavailable || registry.reserveCalls != maxGenerationAttempts {
		t.Fatalf("collision attempts: status=%d calls=%d", collisions.Code, registry.reserveCalls)
	}
	var collisionAudits int
	for _, record := range auditor.records {
		if record.Reason == AuditReasonMaterialCollision {
			collisionAudits++
		}
	}
	if collisionAudits != maxGenerationAttempts {
		t.Fatalf("collision audits=%d", collisionAudits)
	}

	provider, _, registry, _, _ = providerFixture(t)
	registry.activateErr = ErrRegistryUnavailable
	uncertain := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(uncertain, bootstrapHTTPRequest())
	if uncertain.Code != http.StatusServiceUnavailable || registry.reserveCalls != 1 || registry.activateCalls != 1 {
		t.Fatalf("activation uncertainty retried: status=%d reserve=%d activate=%d", uncertain.Code, registry.reserveCalls, registry.activateCalls)
	}
}

func TestProviderAuthenticationConsumesProofBeforeMandatoryAudit(t *testing.T) {
	provider, _, registry, auditor, _ := providerFixture(t)
	auditor.err = errors.New("offline")
	first := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(first, resourceHTTPRequest())
	if first.Code != http.StatusServiceUnavailable || registry.authCalls != 1 {
		t.Fatalf("first authentication: %d calls=%d", first.Code, registry.authCalls)
	}
	auditor.err = nil
	second := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(second, resourceHTTPRequest())
	if second.Code != http.StatusUnauthorized || registry.authCalls != 2 {
		t.Fatalf("consumed proof reused: %d calls=%d", second.Code, registry.authCalls)
	}
	if got := auditor.records[len(auditor.records)-1]; got.Outcome != AuditDeny || got.Reason != AuditReasonProofReplay {
		t.Fatalf("replay audit: %#v", got)
	}
}

func TestProviderDenialAuditFailureBecomesUnavailable(t *testing.T) {
	provider, verifier, registry, auditor, _ := providerFixture(t)
	verifier.proofErr = errInvalid
	denied := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(denied, resourceHTTPRequest())
	if denied.Code != http.StatusUnauthorized || registry.authCalls != 0 || auditor.records[0].Outcome != AuditDeny {
		t.Fatalf("invalid proof boundary: %d auth=%d audit=%#v", denied.Code, registry.authCalls, auditor.records)
	}
	auditor.err = errors.New("offline")
	unavailable := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(unavailable, resourceHTTPRequest())
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing denial audit admitted public denial: %d", unavailable.Code)
	}

	provider, verifier, registry, auditor, _ = providerFixture(t)
	verifier.proofErr = errors.New("unexpected verifier detail")
	unknown := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(unknown, resourceHTTPRequest())
	if unknown.Code != http.StatusServiceUnavailable || registry.authCalls != 0 || auditor.records[0].Outcome != AuditUnavailable || bytes.Contains(unknown.Body.Bytes(), []byte("verifier detail")) {
		t.Fatalf("unknown verifier error escaped: status=%d audit=%#v body=%s", unknown.Code, auditor.records, unknown.Body.String())
	}
}

func TestProviderReadinessRequiresAllThreeBoundaries(t *testing.T) {
	provider, verifier, registry, auditor, _ := providerFixture(t)
	if err := provider.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifier.ready = false
	if !errors.Is(provider.Ready(context.Background()), httpapi.ErrAuthenticationUnavailable) {
		t.Fatal("stale verifier reported ready")
	}
	verifier.ready = true
	registry.status.FenceState = "clock_fenced"
	if !errors.Is(provider.Ready(context.Background()), httpapi.ErrAuthenticationUnavailable) {
		t.Fatal("fenced registry reported ready")
	}
	registry.status.FenceState = "admitted"
	auditor.ready = errors.New("offline")
	if !errors.Is(provider.Ready(context.Background()), httpapi.ErrAuthenticationUnavailable) {
		t.Fatal("offline auditor reported ready")
	}
}

func TestProviderTreatsRegistryInvariantFailureAsUnavailable(t *testing.T) {
	provider, _, registry, auditor, _ := providerFixture(t)
	registry.authenticateErr = ErrRegistryInvalid
	response := httptest.NewRecorder()
	providerHandler(t, provider).ServeHTTP(response, resourceHTTPRequest())
	if response.Code != http.StatusServiceUnavailable || len(auditor.records) != 1 || auditor.records[0].Outcome != AuditUnavailable || auditor.records[0].Reason != AuditReasonRegistryUnavailable {
		t.Fatalf("registry invariant became public denial: status=%d audit=%#v", response.Code, auditor.records)
	}
}

func TestProviderRejectsTypedNilDependencies(t *testing.T) {
	var verifier *fakeTokenVerifier
	var registry *fakeRegistry
	var auditor *fakeAuditor
	if _, err := NewProvider(verifier, &fakeRegistry{}, &fakeAuditor{}); !errors.Is(err, httpapi.ErrAuthenticationUnavailable) {
		t.Fatalf("typed-nil verifier accepted: %v", err)
	}
	if _, err := NewProvider(&fakeTokenVerifier{}, registry, &fakeAuditor{}); !errors.Is(err, httpapi.ErrAuthenticationUnavailable) {
		t.Fatalf("typed-nil registry accepted: %v", err)
	}
	if _, err := NewProvider(&fakeTokenVerifier{}, &fakeRegistry{}, auditor); !errors.Is(err, httpapi.ErrAuthenticationUnavailable) {
		t.Fatalf("typed-nil auditor accepted: %v", err)
	}
}

func TestAuditRecordProfileIsClosed(t *testing.T) {
	provider, _, _, auditor, now := providerFixture(t)
	record := AuditRecord{
		ProfileVersion: providerProfileVersion, OperationID: "01890f3e-7b00-7000-8000-000000000001",
		Operation: AuditAuthentication, Outcome: AuditAllow, Reason: AuditReasonAllowed, DecisionTime: now,
		TenantID: "tenant:example", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ParticipantInstanceID: "01890f3e-7b00-7000-8000-000000000002", SessionEpoch: 1,
		HasDPoPThumbprint: true, DPoPThumbprint: sha256.Sum256([]byte("key")),
	}
	if _, err := provider.recordAudit(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.Reason = AuditReasonInvalidCredential
	if _, err := provider.recordAudit(context.Background(), record); !errors.Is(err, httpapi.ErrAuthenticationUnavailable) || len(auditor.records) != 1 {
		t.Fatalf("malformed audit record crossed port: err=%v records=%d", err, len(auditor.records))
	}
}

func providerFixture(t *testing.T) (*Provider, *fakeTokenVerifier, *fakeRegistry, *fakeAuditor, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	thumbprint := sha256.Sum256([]byte("client-key"))
	verifier := &fakeTokenVerifier{ready: true, bootstrap: BootstrapIdentity{
		TenantID: "tenant:example", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DPoPThumbprint: thumbprint,
		TokenExpiresAt: now.Add(10 * time.Minute), ProofJTI: "bootstrapProofAB", ProofIssuedAt: now,
	}, proof: Proof{JWKThumbprint: thumbprint, JTI: "resourceProofABC", IssuedAt: now}}
	order := []string{}
	registry := &fakeRegistry{order: &order, status: RegistryStatus{FenceState: "admitted"}, active: ActiveSession{
		TenantID: "tenant:example", PrincipalID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ParticipantInstanceID: "01890f3e-7b00-7000-8000-000000000001", SessionEpoch: 7, DPoPThumbprint: thumbprint, ExpiresAt: now.Add(10 * time.Minute),
	}}
	auditor := &fakeAuditor{order: &order}
	ids := idSequence(t)
	provider, err := newProvider(verifier, registry, auditor, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), func() time.Time { return now }, func() (uuid.UUID, error) {
		return <-ids, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider, verifier, registry, auditor, now
}

func idSequence(t *testing.T) <-chan uuid.UUID {
	t.Helper()
	result := make(chan uuid.UUID, 32)
	for index := 1; index <= cap(result); index++ {
		value, err := uuid.Parse("01890f3e-7b00-7000-8000-" + leftPad12(index))
		if err != nil {
			t.Fatal(err)
		}
		result <- value
	}
	return result
}

func leftPad12(value int) string {
	const digits = "000000000000"
	text := []byte(digits)
	for index := len(text) - 1; value > 0; index-- {
		text[index] = byte('0' + value%10)
		value /= 10
	}
	return string(text)
}

func providerHandler(t *testing.T, provider *Provider) *httpapi.Handler {
	t.Helper()
	handler, err := httpapi.New(provider, provider, allowAllAuthorizer{}, inertApplication{}, httpapi.Config{
		PublicBaseURI: providerPublicBase, HeartbeatInterval: time.Hour, MaxStreamLifetime: time.Second, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type allowAllAuthorizer struct{}

func (allowAllAuthorizer) Authorize(context.Context, httpapi.AccessRequest) (httpapi.Decision, error) {
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"allow":true}`), ACLPolicyVersion: "acl-v1", ACLPolicyDigest: "sha-256:test", DecisionReceiptID: "audit:acl:1"}, nil
}

type inertApplication struct{}

func (inertApplication) Append(context.Context, httpapi.AdmittedRequest, []byte) (httpapi.AppendResponse, error) {
	return httpapi.AppendResponse{}, nil
}
func (inertApplication) Replay(context.Context, httpapi.ReplayRequest) ([]byte, error) {
	return []byte(`{"complete":true}`), nil
}
func (inertApplication) Stream(context.Context, httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	items := make(chan httpapi.StreamItem)
	close(items)
	return items, nil
}

func bootstrapHTTPRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, providerPublicBase+"/coordination/v1/sessions", nil)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "DPoP external-token")
	request.Header.Set("DPoP", providerProof)
	return request
}

func resourceHTTPRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, providerTarget, nil)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Authorization", "DPoP AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	request.Header.Set("DPoP", providerProof)
	request.Header.Set("Accept", httpapi.TranscriptMediaType)
	return request
}
