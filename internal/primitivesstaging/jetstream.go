package primitivesstaging

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/coordination/jetstreamkv"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"golang.org/x/sys/unix"
)

const maxNATSCredentialBytes = 16 << 10

type StorageEpochAudit interface {
	RecordStorageEpochValidated(context.Context) error
}

type jetStreamConnection interface {
	IsConnected() bool
	Close()
}

type storageProbe interface {
	ConfiguredEpoch() uint64
	Probe(context.Context) error
}

type jetStreamOpenResult struct {
	connection jetStreamConnection
	nonces     coordination.NonceStore
	leases     coordination.FencedLeaseStore
	budget     coordination.CapabilityBudget
	probes     []storageProbe
}

type jetStreamOpener func(context.Context, *Config, []byte) (*jetStreamOpenResult, error)

type JetStreamComposition struct {
	config     *Config
	connection jetStreamConnection
	nonces     coordination.NonceStore
	leases     coordination.FencedLeaseStore
	budget     coordination.CapabilityBudget
	probes     []storageProbe
	credential []byte
	closed     atomic.Bool
	closeOnce  sync.Once
}

func OpenJetStreamComposition(ctx context.Context, config *Config, descriptors *SecretDescriptors, audit StorageEpochAudit) (*JetStreamComposition, error) {
	return openJetStreamComposition(ctx, config, descriptors, audit, openJetStreamStores)
}

func openJetStreamComposition(ctx context.Context, config *Config, descriptors *SecretDescriptors, audit StorageEpochAudit, opener jetStreamOpener) (*JetStreamComposition, error) {
	if ctx == nil || config == nil || descriptors == nil || audit == nil || opener == nil {
		return nil, ErrInvalid
	}
	descriptor, ok := descriptors.takeNATSCredential()
	if !ok {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(descriptor), "nats-credential")
	if file == nil {
		return nil, ErrUnavailable
	}
	credential, readErr := io.ReadAll(io.LimitReader(file, maxNATSCredentialBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(credential) == 0 || len(credential) > maxNATSCredentialBytes {
		clear(credential)
		return nil, ErrUnavailable
	}
	_ = unix.Mlock(credential)
	result, err := opener(ctx, config, credential)
	if err != nil || result == nil || result.connection == nil || !result.connection.IsConnected() || result.nonces == nil || result.leases == nil || result.budget == nil || len(result.probes) != 2 {
		if result != nil && result.connection != nil {
			result.connection.Close()
		}
		clear(credential)
		_ = unix.Munlock(credential)
		return nil, ErrUnavailable
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, config.NATSRequestTimeout())
	defer cancelProbe()
	for _, probe := range result.probes {
		if probe == nil || probe.ConfiguredEpoch() != config.Epoch() || probe.Probe(probeContext) != nil {
			result.connection.Close()
			clear(credential)
			_ = unix.Munlock(credential)
			return nil, ErrUnavailable
		}
	}
	auditContext, cancelAudit := context.WithTimeout(ctx, config.RequestDeadline())
	defer cancelAudit()
	if audit.RecordStorageEpochValidated(auditContext) != nil {
		result.connection.Close()
		clear(credential)
		_ = unix.Munlock(credential)
		return nil, ErrUnavailable
	}
	return &JetStreamComposition{config: config, connection: result.connection, nonces: result.nonces, leases: result.leases, budget: result.budget, probes: result.probes, credential: credential}, nil
}

func openJetStreamStores(ctx context.Context, config *Config, credential []byte) (*jetStreamOpenResult, error) {
	options := []nats.Option{
		nats.Name("yukh-coordination-private-primitives-staging-v1"),
		nats.UserCredentialBytes(credential),
		nats.Timeout(config.NATSConnectTimeout()),
		nats.NoReconnect(), nats.NoEcho(),
	}
	if strings.HasPrefix(config.NATSServerURI(), "tls://") {
		options = append(options, nats.RootCAs(config.value.TLSTrustBundlePath))
	}
	connection, err := nats.Connect(config.NATSServerURI(), options...)
	if err != nil {
		return nil, ErrUnavailable
	}
	storeConfig := jetstreamkv.Config{
		Replicas: config.NATSReplicas(), Bootstrap: false, MaxLifetime: config.MaxLeaseLifetime(),
		ReplaySafetyWindow: config.NATSReplaySafetyWindow(), Retention: config.NATSRetention(), Epoch: config.Epoch(),
	}
	openContext, cancel := context.WithTimeout(ctx, config.NATSRequestTimeout())
	defer cancel()
	stores, err := jetstreamkv.Open(openContext, connection, storeConfig)
	if err != nil {
		connection.Close()
		return nil, ErrUnavailable
	}
	budget, err := jetstreamkv.OpenCapabilityBudget(openContext, connection, storeConfig, config.CapabilityLimit(), config.CapabilityPendingTTL())
	if err != nil {
		connection.Close()
		return nil, ErrUnavailable
	}
	return &jetStreamOpenResult{connection: connection, nonces: stores, leases: stores, budget: budget, probes: []storageProbe{stores, budget}}, nil
}

func (composition *JetStreamComposition) Ready() bool {
	if composition == nil || composition.closed.Load() || composition.connection == nil || !composition.connection.IsConnected() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), composition.config.NATSRequestTimeout())
	defer cancel()
	for _, probe := range composition.probes {
		if probe == nil || probe.ConfiguredEpoch() != composition.config.Epoch() || probe.Probe(ctx) != nil {
			return false
		}
	}
	return true
}

func (composition *JetStreamComposition) NonceStore() coordination.NonceStore {
	return composition.nonces
}
func (composition *JetStreamComposition) LeaseStore() coordination.FencedLeaseStore {
	return composition.leases
}
func (composition *JetStreamComposition) CapabilityBudget() coordination.CapabilityBudget {
	return composition.budget
}

// NewPrimitivesService binds the three exact JetStream stores to the accepted
// neutral service without exposing any NATS type above this composition.
func (composition *JetStreamComposition) NewPrimitivesService(keys primitives.SealingKeyProvider, now func() time.Time) (*primitives.Service, error) {
	if composition == nil || keys == nil || now == nil || composition.closed.Load() || composition.nonces.ConfiguredEpoch() != composition.config.Epoch() || composition.leases.ConfiguredEpoch() != composition.config.Epoch() || composition.budget.ConfiguredEpoch() != composition.config.Epoch() {
		return nil, ErrInvalid
	}
	sealer, err := primitives.NewProductionAEADSealer(keys)
	if err != nil {
		return nil, ErrUnavailable
	}
	service, err := primitives.NewService(composition.nonces, composition.leases, composition.budget, sealer, primitives.CryptoTokenIDSource{}, composition.config.Epoch(), composition.config.MaxLeaseLifetime(), now)
	if err != nil {
		return nil, ErrUnavailable
	}
	return service, nil
}

func (composition *JetStreamComposition) Close(context.Context) error {
	if composition == nil {
		return ErrInvalid
	}
	composition.closeOnce.Do(func() {
		composition.closed.Store(true)
		if composition.connection != nil {
			composition.connection.Close()
		}
		clear(composition.credential)
		_ = unix.Munlock(composition.credential)
	})
	return nil
}

func (*JetStreamComposition) String() string               { return "JetStreamComposition{REDACTED}" }
func (*JetStreamComposition) GoString() string             { return "JetStreamComposition{REDACTED}" }
func (*JetStreamComposition) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

var _ json.Marshaler = (*JetStreamComposition)(nil)
