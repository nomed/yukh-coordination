package primitivesstaging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination/memory"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
	"github.com/nomed/yukh-coordination/internal/primitiveshttp"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

type readinessFlag struct{ value atomic.Bool }

func (flag *readinessFlag) Ready() bool { return flag.value.Load() }
func (flag *readinessFlag) RecordLifecycle(context.Context, identity.AuditReason) error {
	return nil
}
func (flag *readinessFlag) RecordDependencyUnavailable(context.Context) error        { return nil }
func (flag *readinessFlag) RecordCapabilityKeyLifecycle(context.Context, bool) error { return nil }
func (flag *readinessFlag) Close(context.Context) error {
	flag.value.Store(false)
	return nil
}

type runtimeKeyProvider struct {
	key   primitives.SealingKey
	token atomic.Uint32
}

func (provider *runtimeKeyProvider) Active(context.Context) (primitives.SealingKey, error) {
	return provider.key, nil
}
func (provider *runtimeKeyProvider) Open(context.Context, string) (primitives.SealingKey, error) {
	return provider.key, nil
}
func (provider *runtimeKeyProvider) NewTokenID() ([16]byte, error) {
	return [16]byte{byte(provider.token.Add(1))}, nil
}

func TestRuntimeServesDirectTLSAndLoopbackOperations(t *testing.T) {
	publicListener := testListener(t)
	operationsListener := testListener(t)
	publicAddress, operationsAddress := publicListener.Addr().String(), operationsListener.Addr().String()
	now := time.Now().UTC().Truncate(time.Millisecond)
	config, roots := runtimeConfig(t, publicAddress, operationsAddress, now)
	registration, token, proofKey := testRegistration(t, now)
	replays, err := OpenReplayStore(config.ReplayDatabasePath(), 128, now)
	if err != nil {
		t.Fatal(err)
	}
	defer replays.Close()
	authenticator, _ := NewAuthenticator(registration, replays, func() time.Time { return now })
	auditLedger, err := OpenAuditLedger(config)
	if err != nil {
		t.Fatal(err)
	}
	defer auditLedger.Close()
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	key, _ := primitives.NewSealingKey("staging-key", bytes.Repeat([]byte{1}, 32))
	provider := &runtimeKeyProvider{key: key}
	sealer, _ := primitives.NewAEADSealer(provider, bytes.NewReader(bytes.Repeat([]byte{2}, 256)))
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	service, _ := primitives.NewService(store, store, budget, sealer, provider, 1, time.Minute, func() time.Time { return now })
	auditGate, err := NewAuditGate(context.Background(), authenticator, registration, registration, auditLedger, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	pipeline, _ := primitivesauth.NewPipeline(auditGate, auditGate, auditGate)
	bridge, _ := primitiveshttp.NewBridge(pipeline, service)
	handler, _ := primitiveshttp.NewHandler(bridge, config.PublicBaseURI(), config.Epoch(), config.RequestDeadline(), config.MaxConcurrentRequests())
	tlsConfig, err := LoadServerTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := &readinessFlag{}
	dependencies.value.Store(true)
	readiness, _ := NewReadinessSet(authenticator, auditGate, dependencies)
	custody := &readinessFlag{}
	custody.value.Store(true)
	runtime, err := NewRuntime(config, handler, readiness, tlsConfig, auditGate, custody)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, publicListener, operationsListener) }()
	waitReady(t, "http://"+operationsAddress+"/readyz", http.StatusOK, nil)

	target := config.PublicBaseURI() + "/coordination-primitives/v1/nonces:consume"
	body := `{"epoch":1,"expires_at":"` + now.Add(30*time.Second).Format("2006-01-02T15:04:05.000Z") + `","scope_digest":"` + strings.Repeat("a", 64) + `","value_digest":"` + strings.Repeat("b", 64) + `"}`
	request, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Host = "attacker.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("Content-Type", primitiveshttp.MediaType)
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set("DPoP", testProof(t, proofKey, token, target, now, "runtime-proof-000001"))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS(roots)}}
	dependencies.value.Store(false)
	denied, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unready public status = %d", denied.StatusCode)
	}
	dependencies.value.Store(true)
	request, _ = http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Host = "attacker.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("Content-Type", primitiveshttp.MediaType)
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set("DPoP", testProof(t, proofKey, token, target, now, "runtime-proof-000001"))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(`"outcome":"consumed"`)) {
		t.Fatalf("public response: %d %s", response.StatusCode, responseBody)
	}

	dependencies.value.Store(false)
	waitReady(t, "http://"+operationsAddress+"/readyz", http.StatusServiceUnavailable, nil)
	metrics := getBody(t, "http://"+operationsAddress+"/metrics", nil)
	if metrics != "# TYPE yukh_coordination_staging_ready gauge\nyukh_coordination_staging_ready 0\n" {
		t.Fatalf("metrics = %q", metrics)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if runtime.Ready() {
		t.Fatal("runtime ready after shutdown")
	}
	if err := auditLedger.Verify(context.Background()); err != nil {
		t.Fatalf("audit after shutdown: %v", err)
	}
}

func TestRuntimeRejectsTLS12AndMismatchedListeners(t *testing.T) {
	publicListener := testListener(t)
	operationsListener := testListener(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	config, roots := runtimeConfig(t, publicListener.Addr().String(), operationsListener.Addr().String(), now)
	tlsConfig, err := LoadServerTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _ := newRuntimeHandler(t, config, now)
	ready := &readinessFlag{}
	ready.value.Store(true)
	custody := &readinessFlag{}
	custody.value.Store(true)
	runtime, _ := NewRuntime(config, handler, ready, tlsConfig, ready, custody)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Serve(ctx, publicListener, operationsListener) }()
	waitReady(t, "http://"+config.OperationsBind()+"/livez", http.StatusOK, nil)
	legacy := clientTLS(roots)
	legacy.MinVersion, legacy.MaxVersion = 0x0303, 0x0303
	_, err = (&http.Client{Transport: &http.Transport{TLSClientConfig: legacy}}).Get(config.PublicBaseURI() + "/coordination-primitives/v1/nonces:consume")
	if err == nil {
		t.Fatal("TLS 1.2 unexpectedly admitted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	wrongPublic := testListener(t)
	wrongOperations := testListener(t)
	defer wrongPublic.Close()
	defer wrongOperations.Close()
	secondCustody := &readinessFlag{}
	secondCustody.value.Store(true)
	second, _ := NewRuntime(config, handler, ready, tlsConfig, ready, secondCustody)
	if err := second.Serve(context.Background(), wrongPublic, wrongOperations); err != ErrInvalid {
		t.Fatalf("mismatched listener error = %v", err)
	}
}

func TestTLSLoaderRejectsSymlinkReplacement(t *testing.T) {
	publicListener := testListener(t)
	operationsListener := testListener(t)
	defer publicListener.Close()
	defer operationsListener.Close()
	config, _ := runtimeConfig(t, publicListener.Addr().String(), operationsListener.Addr().String(), time.Now().UTC().Truncate(time.Millisecond))
	replacement := filepath.Join(t.TempDir(), "replacement.pem")
	if err := os.WriteFile(replacement, []byte("not a certificate"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config.value.TLSCertificatePath, config.value.TLSCertificatePath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, config.value.TLSCertificatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerTLSConfig(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink replacement error = %v", err)
	}
}

func newRuntimeHandler(t *testing.T, config *Config, now time.Time) (*primitiveshttp.Handler, string, Readiness) {
	t.Helper()
	registration, token, _ := testRegistration(t, now)
	replays, _ := OpenReplayStore(config.ReplayDatabasePath(), 128, now)
	t.Cleanup(func() { _ = replays.Close() })
	authenticator, _ := NewAuthenticator(registration, replays, func() time.Time { return now })
	store, _ := memory.New(time.Minute, 1, func() time.Time { return now })
	key, _ := primitives.NewSealingKey("staging-key", bytes.Repeat([]byte{1}, 32))
	provider := &runtimeKeyProvider{key: key}
	sealer, _ := primitives.NewAEADSealer(provider, bytes.NewReader(bytes.Repeat([]byte{2}, 256)))
	budget, _ := memory.NewCapabilityBudget(32, time.Second, 1, func() time.Time { return now })
	service, _ := primitives.NewService(store, store, budget, sealer, provider, 1, time.Minute, func() time.Time { return now })
	pipeline, _ := primitivesauth.NewPipeline(authenticator, registration, registration)
	bridge, _ := primitiveshttp.NewBridge(pipeline, service)
	handler, _ := primitiveshttp.NewHandler(bridge, config.PublicBaseURI(), config.Epoch(), config.RequestDeadline(), config.MaxConcurrentRequests())
	return handler, token, authenticator
}

func runtimeConfig(t *testing.T, publicAddress, operationsAddress string, now time.Time) (*Config, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certificatePEM, keyPEM := testCertificate(t, now)
	files := map[string][]byte{"tls.crt": certificatePEM, "tls.key": keyPEM, "ca.crt": certificatePEM, "registration.json": []byte("fixture"), "registration.sig": []byte("fixture")}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	value := configJSON{
		Profile: Profile, PublicBaseURI: "https://" + publicAddress, PublicBind: publicAddress, OperationsBind: operationsAddress,
		TLSCertificatePath: filepath.Join(dir, "tls.crt"), TLSPrivateKeyPath: filepath.Join(dir, "tls.key"), TLSTrustBundlePath: filepath.Join(dir, "ca.crt"),
		RegistrationPath: filepath.Join(dir, "registration.json"), RegistrationSignaturePath: filepath.Join(dir, "registration.sig"), ReplayDatabasePath: filepath.Join(dir, "replays.db"),
		AuditDatabasePath: filepath.Join(dir, "audit.db"),
		RegistrationKeyID: "coordination-staging-1", RegistrationPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RequestDeadlineMS: 1000, MaxConcurrentRequests: 8, MaxReplayEntries: 128, MaxLeaseLifetimeMS: 60_000,
		NATSServerURI: "nats://127.0.0.1:4222", NATSConnectTimeoutMS: 1000, NATSRequestTimeoutMS: 1000, NATSReplicas: 1,
		NATSReplaySafetyWindowMS: 300_000, NATSRetentionMS: 3_600_000, CapabilityLimit: 8, CapabilityPendingTTLMS: 500, Epoch: 1,
	}
	raw, _ := json.Marshal(value)
	config, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("failed to create roots")
	}
	return config, roots
}

func testCertificate(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hermetic staging"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func clientTLS(roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
}

func testListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func waitReady(t *testing.T, address string, status int, client *http.Client) {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(address)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == status {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not return %d", address, status)
}

func getBody(t *testing.T, address string, client *http.Client) string {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Get(address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return string(raw)
}
