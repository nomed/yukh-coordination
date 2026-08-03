package primitivesstaging

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nomed/yukh-coordination/internal/primitivesauth"
	"github.com/nomed/yukh-coordination/internal/primitiveshttp"
	auditsqlite "github.com/nomed/yukh-coordination/internal/relay/audit/sqlite"
)

// Application is the closed RFC-0022 executable assembly. It owns every
// runtime dependency but exposes no configuration or secret-bearing member.
type Application struct {
	runtime      *Runtime
	dependencies *ReadinessSet
	custody      *CapabilityKeyring
	replays      *ReplayStore
	audit        *auditsqlite.Ledger
	started      atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

func OpenApplication(ctx context.Context, configPath string, descriptors *SecretDescriptors, now func() time.Time) (*Application, error) {
	return openApplication(ctx, configPath, descriptors, now, openJetStreamStores)
}

func openApplication(ctx context.Context, configPath string, descriptors *SecretDescriptors, now func() time.Time, storageOpener jetStreamOpener) (_ *Application, resultErr error) {
	if ctx == nil || descriptors == nil || now == nil || storageOpener == nil {
		return nil, ErrInvalid
	}
	observed := now().UTC().Truncate(time.Millisecond)
	if !validMillisecond(observed) {
		return nil, ErrInvalid
	}
	config, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, ErrInvalid
	}
	tlsConfig, err := LoadServerTLSConfig(config)
	if err != nil {
		return nil, ErrInvalid
	}
	registration, err := LoadRegistration(config, observed)
	if err != nil {
		return nil, ErrInvalid
	}
	application := &Application{}
	defer func() {
		if resultErr != nil {
			_ = application.Close(context.Background())
		}
	}()
	application.replays, err = OpenReplayStore(config.ReplayDatabasePath(), config.MaxReplayEntries(), observed)
	if err != nil {
		return nil, ErrUnavailable
	}
	application.audit, err = OpenAuditLedger(config)
	if err != nil {
		return nil, ErrUnavailable
	}
	authenticator, err := NewAuthenticator(registration, application.replays, now)
	if err != nil {
		return nil, ErrUnavailable
	}
	auditGate, err := NewAuditGate(ctx, authenticator, registration, registration, application.audit, now)
	if err != nil {
		return nil, ErrUnavailable
	}
	application.custody, err = OpenCapabilityKeyring(ctx, descriptors, config.MaxLeaseLifetime(), now, auditGate)
	if err != nil {
		return nil, ErrUnavailable
	}
	storage, err := openJetStreamComposition(ctx, config, descriptors, auditGate, storageOpener)
	if err != nil {
		return nil, ErrUnavailable
	}
	service, err := storage.NewPrimitivesService(application.custody, now)
	if err != nil {
		_ = storage.Close(ctx)
		return nil, ErrUnavailable
	}
	pipeline, err := primitivesauth.NewPipeline(auditGate, auditGate, auditGate)
	if err != nil {
		_ = storage.Close(ctx)
		return nil, ErrUnavailable
	}
	bridge, err := primitiveshttp.NewBridge(pipeline, service)
	if err != nil {
		_ = storage.Close(ctx)
		return nil, ErrUnavailable
	}
	handler, err := primitiveshttp.NewHandler(bridge, config.PublicBaseURI(), config.Epoch(), config.RequestDeadline(), config.MaxConcurrentRequests())
	if err != nil {
		_ = storage.Close(ctx)
		return nil, ErrUnavailable
	}
	application.dependencies, err = NewReadinessSet(authenticator, auditGate, storage)
	if err != nil {
		_ = storage.Close(ctx)
		return nil, ErrUnavailable
	}
	application.runtime, err = NewRuntime(config, handler, application.dependencies, tlsConfig, auditGate, application.custody)
	if err != nil {
		return nil, ErrUnavailable
	}
	return application, nil
}

func (application *Application) Run(ctx context.Context) error {
	if application == nil || ctx == nil || application.runtime == nil || !application.started.CompareAndSwap(false, true) {
		return ErrInvalid
	}
	defer application.Close(context.Background())
	if err := application.runtime.ListenAndServe(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (application *Application) Ready() bool {
	return application != nil && application.runtime != nil && application.runtime.Ready()
}

func (application *Application) Close(ctx context.Context) error {
	if application == nil || ctx == nil {
		return ErrInvalid
	}
	application.closeOnce.Do(func() {
		if application.dependencies != nil {
			if err := application.dependencies.Close(ctx); err != nil {
				application.closeErr = ErrUnavailable
			}
		}
		if application.custody != nil {
			if err := application.custody.Close(ctx); err != nil {
				application.closeErr = ErrUnavailable
			}
		}
		if application.replays != nil {
			if err := application.replays.Close(); err != nil {
				application.closeErr = ErrUnavailable
			}
		}
		if application.audit != nil {
			if err := application.audit.Close(); err != nil {
				application.closeErr = ErrUnavailable
			}
		}
	})
	return application.closeErr
}

func (*Application) String() string               { return "Application{REDACTED}" }
func (*Application) GoString() string             { return "Application{REDACTED}" }
func (*Application) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
