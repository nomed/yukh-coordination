package primitivesstaging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
	"golang.org/x/sys/unix"
)

func TestApplicationComposesServesAndClosesEveryOwnedDependency(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	configPath, descriptors, auditPath := applicationFixtureFiles(t, now)
	connection := &connectionFixture{}
	connection.connected.Store(true)
	probe := &storageProbeFixture{epoch: 1}
	application, err := openApplication(context.Background(), configPath, descriptors, func() time.Time { return now }, memoryJetStreamOpener(connection, probe, probe))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(application); !errors.Is(err, ErrInvalid) {
		t.Fatalf("application JSON error = %v", err)
	}
	backing := application.custody.keys[application.custody.active].material
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.Run(ctx) }()
	config, _ := LoadConfigFile(configPath)
	waitReady(t, "http://"+config.OperationsBind()+"/readyz", http.StatusOK, nil)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if application.Ready() || connection.IsConnected() || !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Fatal("application retained readiness, connection, or key material")
	}
	ledger, err := auditsqlite.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	if err := ledger.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationRejectsRelativeConfigBeforeDescriptors(t *testing.T) {
	descriptors, descriptor, keyDescriptor := applicationDescriptors(t, []byte("unused"), []byte("unused"))
	_, err := openApplication(context.Background(), "relative.json", descriptors, time.Now, func(context.Context, *Config, []byte) (*jetStreamOpenResult, error) {
		t.Fatal("storage opener reached")
		return nil, nil
	})
	if err != ErrInvalid {
		t.Fatalf("relative config error = %v", err)
	}
	if _, err := unix.Seek(descriptor, 0, 0); err != nil {
		t.Fatal("descriptor was consumed before config validation")
	}
	_ = unix.Close(descriptor)
	_ = unix.Close(keyDescriptor)
}

func applicationFixtureFiles(t *testing.T, now time.Time) (string, *SecretDescriptors, string) {
	t.Helper()
	publicAddress := reserveAddress(t)
	operationsAddress := reserveAddress(t)
	dir := t.TempDir()
	certificate, privateKey := testCertificate(t, now)
	policyPublic, policyPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := registrationJSON{
		Actions:        []string{"coordination.nonce.consume", "coordination.lease.acquire", "coordination.lease.inspect", "coordination.lease.renew", "coordination.lease.release"},
		DPoPThumbprint: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		ExpiresAt:      now.Add(10 * time.Minute).Format("2006-01-02T15:04:05.000Z"), IssuedAt: now.Format("2006-01-02T15:04:05.000Z"),
		KeyID: "policy-key-1", PrincipalID: "mcp-staging", Profile: registrationProfile, TenantID: "tenant-a",
		TokenDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
	}
	registrationRaw, _ := json.Marshal(registration)
	registrationRaw, err = jsoncanonicalizer.Transform(registrationRaw)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"tls.crt": certificate, "tls.key": privateKey, "ca.crt": certificate,
		"registration.json": registrationRaw,
		"registration.sig":  []byte(base64.RawURLEncoding.EncodeToString(ed25519.Sign(policyPrivate, registrationRaw))),
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	auditPath := filepath.Join(dir, "audit.db")
	value := configJSON{
		Profile: Profile, PublicBaseURI: "https://" + publicAddress, PublicBind: publicAddress, OperationsBind: operationsAddress,
		TLSCertificatePath: filepath.Join(dir, "tls.crt"), TLSPrivateKeyPath: filepath.Join(dir, "tls.key"), TLSTrustBundlePath: filepath.Join(dir, "ca.crt"),
		RegistrationPath: filepath.Join(dir, "registration.json"), RegistrationSignaturePath: filepath.Join(dir, "registration.sig"), ReplayDatabasePath: filepath.Join(dir, "replay.db"), AuditDatabasePath: auditPath,
		RegistrationKeyID: registration.KeyID, RegistrationPublicKey: base64.RawURLEncoding.EncodeToString(policyPublic),
		RequestDeadlineMS: 1000, MaxConcurrentRequests: 8, MaxReplayEntries: 128, MaxLeaseLifetimeMS: 60_000,
		NATSServerURI: "nats://127.0.0.1:4222", NATSConnectTimeoutMS: 1000, NATSRequestTimeoutMS: 1000, NATSReplicas: 1,
		NATSReplaySafetyWindowMS: 300_000, NATSRetentionMS: 3_600_000, CapabilityLimit: 8, CapabilityPendingTTLMS: 500, Epoch: 1,
	}
	configRaw, _ := json.Marshal(value)
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, configRaw, 0o440); err != nil {
		t.Fatal(err)
	}
	keyring := canonicalKeyring(t, []capabilityKeyJSON{keyJSON("active-key", bytes.Repeat([]byte{4}, 32), now.Add(-time.Minute), now.Add(time.Minute), now.Add(2*time.Minute))})
	descriptors, _, _ := applicationDescriptors(t, []byte("synthetic-nats-credential"), keyring)
	return configPath, descriptors, auditPath
}

func applicationDescriptors(t *testing.T, natsCredential, keyring []byte) (*SecretDescriptors, int, int) {
	t.Helper()
	natsDescriptor := memfdBytes(t, "nats-credential", natsCredential)
	keyDescriptor := memfdBytes(t, "capability-keyring", keyring)
	descriptors, err := NewSecretDescriptors(natsDescriptor, keyDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	return descriptors, natsDescriptor, keyDescriptor
}

func memfdBytes(t *testing.T, name string, raw []byte) int {
	t.Helper()
	descriptor, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if written, err := unix.Write(descriptor, raw); err != nil || written != len(raw) {
		t.Fatal(err)
	}
	if _, err := unix.Seek(descriptor, 0, 0); err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
