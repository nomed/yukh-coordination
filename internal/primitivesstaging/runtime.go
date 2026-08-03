package primitivesstaging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomed/yukh-coordination/internal/primitiveshttp"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const maxTLSFileBytes = 1 << 20

const unavailableProblem = `{"code":"temporarily_unavailable","status":503,"title":"temporarily_unavailable","type":"urn:yukh:coordination-primitives:problem:temporarily_unavailable"}`

type Readiness interface {
	Ready() bool
}

type LifecycleAuditor interface {
	RecordLifecycle(context.Context, identity.AuditReason) error
	RecordDependencyUnavailable(context.Context) error
	Ready() bool
}

type ReadinessSet struct{ probes []Readiness }

func NewReadinessSet(probes ...Readiness) (*ReadinessSet, error) {
	if len(probes) == 0 {
		return nil, ErrInvalid
	}
	copyOfProbes := make([]Readiness, len(probes))
	for index, probe := range probes {
		if probe == nil {
			return nil, ErrInvalid
		}
		copyOfProbes[index] = probe
	}
	return &ReadinessSet{probes: copyOfProbes}, nil
}

func (set *ReadinessSet) Ready() bool {
	if set == nil || len(set.probes) == 0 {
		return false
	}
	for _, probe := range set.probes {
		if probe == nil || !probe.Ready() {
			return false
		}
	}
	return true
}

type Runtime struct {
	config     *Config
	handler    *primitiveshttp.Handler
	dependency Readiness
	tlsConfig  *tls.Config
	audit      LifecycleAuditor
	running    atomic.Bool
	stopping   atomic.Bool
	mu         sync.Mutex
	public     *http.Server
	operations *http.Server
}

func LoadServerTLSConfig(config *Config) (*tls.Config, error) {
	if config == nil || config.ValidatePaths() != nil {
		return nil, ErrInvalid
	}
	certificatePEM, err := boundedFile(config.value.TLSCertificatePath)
	if err != nil {
		return nil, ErrInvalid
	}
	keyPEM, err := boundedFile(config.value.TLSPrivateKeyPath)
	if err != nil {
		return nil, ErrInvalid
	}
	trustPEM, err := boundedFile(config.value.TLSTrustBundlePath)
	if err != nil {
		return nil, ErrInvalid
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trustPEM) {
		return nil, ErrInvalid
	}
	base, err := url.Parse(config.PublicBaseURI())
	if err != nil {
		return nil, ErrInvalid
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, ErrInvalid
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: base.Hostname(), Roots: roots, Intermediates: intermediates, CurrentTime: time.Now().UTC()}); err != nil {
		return nil, ErrInvalid
	}
	pair.Leaf = leaf
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func NewRuntime(config *Config, handler *primitiveshttp.Handler, dependency Readiness, tlsConfig *tls.Config, audit LifecycleAuditor) (*Runtime, error) {
	if config == nil || handler == nil || dependency == nil || audit == nil || !validServerTLS(tlsConfig) {
		return nil, ErrInvalid
	}
	return &Runtime{config: config, handler: handler, dependency: dependency, tlsConfig: tlsConfig.Clone(), audit: audit}, nil
}

func (r *Runtime) Ready() bool {
	return r != nil && r.running.Load() && !r.stopping.Load() && r.dependency != nil && r.dependency.Ready()
}

func (r *Runtime) ListenAndServe(ctx context.Context) error {
	if r == nil {
		return ErrInvalid
	}
	publicListener, err := exactListener(r.config.PublicBind())
	if err != nil {
		return err
	}
	operationsListener, err := exactListener(r.config.OperationsBind())
	if err != nil {
		_ = publicListener.Close()
		return err
	}
	return r.Serve(ctx, publicListener, operationsListener)
}

// Serve owns both pre-bound listeners until context cancellation or failure.
// Passing listeners makes address allocation explicit and keeps qualification
// hermetic; their addresses must exactly equal the closed configuration.
func (r *Runtime) Serve(ctx context.Context, publicListener, operationsListener net.Listener) error {
	if r == nil || ctx == nil || publicListener == nil || operationsListener == nil || publicListener.Addr().String() != r.config.PublicBind() || operationsListener.Addr().String() != r.config.OperationsBind() {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.public != nil || r.operations != nil || r.stopping.Load() {
		r.mu.Unlock()
		return ErrInvalid
	}
	if !r.audit.Ready() || r.audit.RecordLifecycle(ctx, identity.AuditReasonTLSReady) != nil || r.audit.RecordLifecycle(ctx, identity.AuditReasonStarted) != nil {
		r.mu.Unlock()
		_ = publicListener.Close()
		_ = operationsListener.Close()
		return ErrUnavailable
	}
	publicServer := boundedServer(r.config.PublicBind(), r.publicHandler())
	operationsServer := boundedServer(r.config.OperationsBind(), r.operationsHandler())
	r.public, r.operations = publicServer, operationsServer
	r.running.Store(true)
	r.mu.Unlock()

	errorsSeen := make(chan error, 2)
	go func() { errorsSeen <- publicServer.Serve(tls.NewListener(publicListener, r.tlsConfig.Clone())) }()
	go func() { errorsSeen <- operationsServer.Serve(operationsListener) }()

	var result error
	select {
	case <-ctx.Done():
	case err := <-errorsSeen:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			result = ErrUnavailable
		}
	}
	r.stopping.Store(true)
	r.running.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), r.config.RequestDeadline())
	defer cancel()
	if err := publicServer.Shutdown(shutdownCtx); err != nil {
		_ = publicServer.Close()
		result = ErrUnavailable
	}
	if err := operationsServer.Shutdown(shutdownCtx); err != nil {
		_ = operationsServer.Close()
		result = ErrUnavailable
	}
	auditCtx, auditCancel := context.WithTimeout(context.Background(), r.config.RequestDeadline())
	defer auditCancel()
	if err := r.audit.RecordLifecycle(auditCtx, identity.AuditReasonStopped); err != nil {
		result = ErrUnavailable
	}
	return result
}

func (r *Runtime) publicHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !r.Ready() {
			_ = r.audit.RecordDependencyUnavailable(request.Context())
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("Content-Type", primitiveshttp.MediaType)
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(unavailableProblem))
			return
		}
		r.handler.ServeHTTP(writer, request)
	})
}

func (r *Runtime) operationsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("live\n"))
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !r.Ready() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("unready\n"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
		ready := 0
		if r.Ready() {
			ready = 1
		}
		_, _ = fmt.Fprintf(writer, "# TYPE yukh_coordination_staging_ready gauge\nyukh_coordination_staging_ready %d\n", ready)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != r.config.OperationsBind() || request.URL.RawQuery != "" || request.URL.Fragment != "" {
			http.NotFound(writer, request)
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

func boundedServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func validServerTLS(config *tls.Config) bool {
	return config != nil && config.MinVersion == tls.VersionTLS13 && config.MaxVersion == tls.VersionTLS13 && len(config.Certificates) == 1 && config.GetCertificate == nil && config.GetConfigForClient == nil && config.ClientAuth == tls.NoClientCert
}

func boundedFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || !os.SameFile(info, after) || info.Size() < 1 || info.Size() > maxTLSFileBytes {
		return nil, ErrInvalid
	}
	buffer := make([]byte, info.Size())
	if _, err := io.ReadFull(file, buffer); err != nil {
		return nil, ErrInvalid
	}
	return buffer, nil
}

func exactListener(address string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrInvalid
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort == 0 || net.ParseIP(host) == nil {
		return nil, ErrInvalid
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, ErrUnavailable
	}
	return listener, nil
}
