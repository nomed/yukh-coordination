package runtime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/memory"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
	"github.com/nomed/yukh-coordination/internal/relay/service"
)

func TestRuntimeComposesRealRequestAndStopsInReverseOrder(t *testing.T) {
	fixture := newRuntimeFixture(t)
	var closeMu sync.Mutex
	var closeOrder []string
	fixture.config.Resources = []Resource{
		{Name: "store", Close: func(context.Context) error {
			closeMu.Lock()
			defer closeMu.Unlock()
			closeOrder = append(closeOrder, "store")
			return nil
		}},
		{Name: "connection", Close: func(context.Context) error {
			closeMu.Lock()
			defer closeMu.Unlock()
			closeOrder = append(closeOrder, "connection")
			return nil
		}},
	}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.State() != StateConstructed {
		t.Fatalf("state = %s", runtime.State())
	}
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- runtime.Run(ctx) }()
	waitReady(t, runtime)

	event, err := os.ReadFile(filepath.Join(repositoryRoot(t), "conformance/fixtures/positive/event-join.json"))
	if err != nil {
		t.Fatal(err)
	}
	canonicalEvent, err := protocol.Canonicalize(event)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, fixture.baseURL+"/coordination/v1/channels/channel:release/transcripts/0/events", bytes.NewReader(canonicalEvent))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer runtime-test")
	request.Header.Set("Content-Type", "application/yukh-event+json;version=0.1")
	response, err := fixture.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || fixture.authenticator.calls.Load() != 1 || fixture.authorizer.calls.Load() != 1 || fixture.signer.signCalls.Load() != 1 {
		t.Fatalf("request did not traverse composition: status=%d body=%s authn=%d authz=%d sign=%d", response.StatusCode, body, fixture.authenticator.calls.Load(), fixture.authorizer.calls.Load(), fixture.signer.signCalls.Load())
	}
	records, err := fixture.store.Read(context.Background(), fixture.channel.Key, 0, 10)
	if err != nil || len(records) != 1 || len(records[0].Signature) != 64 {
		t.Fatalf("durable append missing: %#v, %v", records, err)
	}

	streamRequest, _ := http.NewRequest(http.MethodGet, fixture.baseURL+"/coordination/v1/channels/channel:release/transcripts/0/stream", nil)
	streamRequest.Header.Set("Authorization", "Bearer runtime-test")
	streamRequest.Header.Set("Accept", "text/event-stream")
	streamRequest.Header.Set("Last-Event-ID", "1")
	streamResponse, err := fixture.client.Do(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	streamPrefix := make([]byte, len("retry: 3000\n\n"))
	if _, err := io.ReadFull(streamResponse.Body, streamPrefix); err != nil || string(streamPrefix) != "retry: 3000\n\n" {
		t.Fatalf("SSE did not start: %q, %v", streamPrefix, err)
	}

	cancel()
	if err := <-runResult; err != nil {
		t.Fatal(err)
	}
	if runtime.State() != StateStopped {
		t.Fatalf("state = %s", runtime.State())
	}
	select {
	case <-runtime.Done():
	default:
		t.Fatal("Done was not closed")
	}
	if _, err := streamResponse.Body.Read(make([]byte, 1)); err == nil {
		t.Fatal("SSE survived runtime cancellation")
	}
	_ = streamResponse.Body.Close()
	closeMu.Lock()
	defer closeMu.Unlock()
	if strings.Join(closeOrder, ",") != "connection,store" {
		t.Fatalf("close order = %v", closeOrder)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrAlreadyRun) {
		t.Fatalf("second Run = %v", err)
	}
}

func TestRuntimeForcesBlockedRequestAtDeadline(t *testing.T) {
	fixture := newRuntimeFixture(t)
	block := make(chan struct{})
	entered := make(chan struct{})
	fixture.authenticator.block = block
	fixture.authenticator.entered = entered
	fixture.config.Server.ShutdownTimeout = 30 * time.Millisecond
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- runtime.Run(ctx) }()
	waitReady(t, runtime)
	request, _ := http.NewRequest(http.MethodGet, fixture.baseURL+"/coordination/v1/channels/channel:release/transcripts/0/records", nil)
	request.Header.Set("Authorization", "Bearer runtime-test")
	request.Header.Set("Accept", httpapi.TranscriptMediaType)
	clientResult := make(chan error, 1)
	go func() {
		response, requestErr := fixture.client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		clientResult <- requestErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach authenticator")
	}
	cancel()
	runErr := <-runResult
	if !errors.Is(runErr, context.DeadlineExceeded) || runtime.State() != StateFailed {
		t.Fatalf("forced shutdown = %v, state=%s", runErr, runtime.State())
	}
	close(block)
	select {
	case <-clientResult:
	case <-time.After(time.Second):
		t.Fatal("forced close did not release client")
	}
}

func TestRuntimeBoundsOwnedResourceCleanup(t *testing.T) {
	fixture := newRuntimeFixture(t)
	fixture.config.Server.ShutdownTimeout = 30 * time.Millisecond
	fixture.config.Resources = []Resource{{Name: "blocking", Close: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	waitReady(t, runtime)
	cancel()
	select {
	case runErr := <-result:
		if !errors.Is(runErr, context.DeadlineExceeded) || runtime.State() != StateFailed {
			t.Fatalf("cleanup deadline = %v, state=%s", runErr, runtime.State())
		}
	case <-time.After(time.Second):
		t.Fatal("resource cleanup ignored its deadline")
	}
}

func TestRuntimeRedactsAndJoinsServeAndCloseFailures(t *testing.T) {
	serveFailure := errors.New("serve secret material")
	firstFailure := errors.New("first bearer secret")
	secondFailure := errors.New("second key secret")
	listener := &failingListener{err: serveFailure}
	fixture := newRuntimeFixtureWithListener(t, listener)
	var closeMu sync.Mutex
	var order []string
	fixture.config.Resources = []Resource{
		{Name: "first", Close: func(context.Context) error {
			closeMu.Lock()
			defer closeMu.Unlock()
			order = append(order, "first")
			return firstFailure
		}},
		{Name: "second", Close: func(context.Context) error {
			closeMu.Lock()
			defer closeMu.Unlock()
			order = append(order, "second")
			return secondFailure
		}},
	}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	runErr := runtime.Run(context.Background())
	if !errors.Is(runErr, serveFailure) || !errors.Is(runErr, firstFailure) || !errors.Is(runErr, secondFailure) {
		t.Fatalf("joined failures were lost: %v", runErr)
	}
	if strings.Contains(runErr.Error(), "secret") {
		t.Fatalf("lifecycle error leaked provider text: %v", runErr)
	}
	if strings.Join(order, ",") != "second,first" || listener.closeCalls.Load() != 1 {
		t.Fatalf("cleanup mismatch: order=%v closes=%d", order, listener.closeCalls.Load())
	}
	if runtime.State() != StateFailed {
		t.Fatalf("state = %s", runtime.State())
	}
}

func TestConcurrentCancellationAndServeFailureCloseResourcesOnce(t *testing.T) {
	listener := newTriggeredListener(errors.New("accept failed"))
	fixture := newRuntimeFixtureWithListener(t, listener)
	var closes atomic.Int32
	fixture.config.Resources = []Resource{{Name: "owned", Close: func(context.Context) error { closes.Add(1); return nil }}}
	runtime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	waitReady(t, runtime)
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); cancel() }()
	go func() { defer group.Done(); listener.Fail() }()
	group.Wait()
	<-result
	if closes.Load() != 1 {
		t.Fatalf("resource closed %d times", closes.Load())
	}
}

func TestNewRejectsIncompleteOrAmbiguousComposition(t *testing.T) {
	tests := map[string]func(*Config){
		"store": func(c *Config) { c.Store = nil }, "subscriptions": func(c *Config) { c.Subscriptions = nil },
		"typed-nil-store": func(c *Config) { c.Store = (*memory.Store)(nil) },
		"authenticator":   func(c *Config) { c.Authenticator = nil }, "authorizer": func(c *Config) { c.Authorizer = nil },
		"signer": func(c *Config) { c.Signer = nil }, "validator": func(c *Config) { c.Validator = nil },
		"listener":            func(c *Config) { c.Listener = nil },
		"heartbeat":           func(c *Config) { c.Server.HTTP.HeartbeatInterval = 0 },
		"stream-lifetime":     func(c *Config) { c.Server.HTTP.MaxStreamLifetime = 16 * time.Minute },
		"write-timeout":       func(c *Config) { c.Server.HTTP.WriteTimeout = 0 },
		"read-header-timeout": func(c *Config) { c.Server.ReadHeaderTimeout = 0 },
		"idle-timeout":        func(c *Config) { c.Server.IdleTimeout = 0 },
		"header-limit-low":    func(c *Config) { c.Server.MaxHeaderBytes = 100 },
		"header-limit-high":   func(c *Config) { c.Server.MaxHeaderBytes = 1<<20 + 1 },
		"shutdown-timeout":    func(c *Config) { c.Server.ShutdownTimeout = 0 },
		"duplicate-resource": func(c *Config) {
			c.Resources = []Resource{{Name: "same", Close: func(context.Context) error { return nil }}, {Name: "same", Close: func(context.Context) error { return nil }}}
		},
		"unsafe-resource-name": func(c *Config) {
			c.Resources = []Resource{{Name: "token=secret", Close: func(context.Context) error { return nil }}}
		},
		"nil-resource-close": func(c *Config) { c.Resources = []Resource{{Name: "resource"}} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newRuntimeFixture(t)
			mutate(&fixture.config)
			if _, err := New(fixture.config); !errors.Is(err, relay.ErrInvalidArgument) {
				t.Fatalf("New = %v", err)
			}
		})
	}
}

type runtimeFixture struct {
	config        Config
	store         *memory.Store
	channel       relay.Channel
	authenticator *testAuthenticator
	authorizer    *testAuthorizer
	signer        *testSigner
	client        *http.Client
	baseURL       string
}

func newRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tlsListener := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, MinVersion: tls.VersionTLS13})
	fixture := newRuntimeFixtureWithListener(t, tlsListener)
	fixture.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}, Timeout: 2 * time.Second} // test-only certificate
	t.Cleanup(fixture.client.CloseIdleConnections)
	fixture.baseURL = "https://" + raw.Addr().String()
	return fixture
}

func newRuntimeFixtureWithListener(t *testing.T, listener net.Listener) runtimeFixture {
	t.Helper()
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := os.ReadFile(filepath.Join(repositoryRoot(t), "conformance/canonical/channel.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	validated, err := validator.ValidateChannelMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	channel := relay.Channel{Key: relay.ChannelKey{TenantID: "tenant:example", ChannelID: "channel:release", TranscriptEpoch: "0"}, URI: validated.ChannelURI, CanonicalMetadata: metadata, MetadataDigest: validated.Digest, Lifecycle: "active"}
	store := memory.New()
	if err := store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	authenticator := &testAuthenticator{}
	authorizer := &testAuthorizer{}
	signer := &testSigner{}
	return runtimeFixture{store: store, channel: channel, authenticator: authenticator, authorizer: authorizer, signer: signer, config: Config{
		Store: store, Subscriptions: service.NewLiveChanges(), Authenticator: authenticator, Authorizer: authorizer, Signer: signer, Validator: validator, Listener: listener,
		Server: ServerConfig{HTTP: httpapi.Config{HeartbeatInterval: 50 * time.Millisecond, MaxStreamLifetime: time.Minute, WriteTimeout: time.Second}, ReadHeaderTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16_384, ShutdownTimeout: time.Second},
	}}
}

type testAuthenticator struct {
	calls   atomic.Int32
	block   <-chan struct{}
	entered chan<- struct{}
}

func (a *testAuthenticator) Authenticate(context.Context, string) (httpapi.Identity, error) {
	a.calls.Add(1)
	if a.entered != nil {
		close(a.entered)
	}
	if a.block != nil {
		<-a.block
	}
	return httpapi.Identity{TenantID: "tenant:example", PrincipalID: "principal:fixture", ParticipantInstanceID: "01989f0e-56b7-7e01-915e-a7748f7f6220", SessionEpoch: 1}, nil
}

type testAuthorizer struct{ calls atomic.Int32 }

func (a *testAuthorizer) Authorize(context.Context, httpapi.AccessRequest) (httpapi.Decision, error) {
	a.calls.Add(1)
	return httpapi.Decision{Allowed: true, CanonicalBinding: []byte(`{"decision":"allow"}`), ACLPolicyVersion: "acl-v1", ACLPolicyDigest: "sha-256:1111111111111111111111111111111111111111111111111111111111111111", DecisionReceiptID: "decision-1", Revoked: make(chan struct{})}, nil
}

type testSigner struct{ signCalls atomic.Int32 }

func (*testSigner) Select(context.Context) (service.SigningSelection, error) {
	return service.SigningSelection{KeyID: "key-1", Algorithm: "ed25519"}, nil
}
func (s *testSigner) Sign(context.Context, relay.AcceptedRecord) ([]byte, error) {
	s.signCalls.Add(1)
	return bytes.Repeat([]byte{0}, 64), nil
}

type failingListener struct {
	err        error
	closeCalls atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *failingListener) Close() error              { l.closeCalls.Add(1); return nil }
func (*failingListener) Addr() net.Addr              { return testAddress("runtime-test") }

type testAddress string

func (a testAddress) Network() string { return string(a) }
func (a testAddress) String() string  { return string(a) }

type triggeredListener struct {
	err     error
	release chan struct{}
	once    sync.Once
}

func newTriggeredListener(err error) *triggeredListener {
	return &triggeredListener{err: err, release: make(chan struct{})}
}

func (l *triggeredListener) Accept() (net.Conn, error) { <-l.release; return nil, l.err }
func (l *triggeredListener) Close() error              { l.Fail(); return nil }
func (*triggeredListener) Addr() net.Addr              { return testAddress("triggered-runtime-test") }
func (l *triggeredListener) Fail()                     { l.once.Do(func() { close(l.release) }) }

func waitReady(t *testing.T, runtime *Runtime) {
	t.Helper()
	select {
	case <-runtime.Ready():
	case <-time.After(time.Second):
		t.Fatal("runtime did not become ready")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "runtime-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
