package primitivesstaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination/memory"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"golang.org/x/sys/unix"
)

type storageAuditFixture struct {
	called int
	err    error
}

func (fixture *storageAuditFixture) RecordStorageEpochValidated(context.Context) error {
	fixture.called++
	return fixture.err
}

type connectionFixture struct{ connected atomic.Bool }

func (fixture *connectionFixture) IsConnected() bool { return fixture.connected.Load() }
func (fixture *connectionFixture) Close()            { fixture.connected.Store(false) }

type storageProbeFixture struct {
	epoch uint64
	err   atomic.Bool
}

func (fixture *storageProbeFixture) ConfiguredEpoch() uint64 { return fixture.epoch }
func (fixture *storageProbeFixture) Probe(context.Context) error {
	if fixture.err.Load() {
		return errors.New("private dependency detail")
	}
	return nil
}

func TestJetStreamCompositionConsumesDescriptorAndFailsReadinessClosed(t *testing.T) {
	config := jetStreamTestConfig(t)
	descriptors, descriptor := natsDescriptorFixture(t, []byte("synthetic-nats-credential"))
	connection := &connectionFixture{}
	connection.connected.Store(true)
	storeProbe := &storageProbeFixture{epoch: config.Epoch()}
	budgetProbe := &storageProbeFixture{epoch: config.Epoch()}
	audit := &storageAuditFixture{}
	composition, err := openJetStreamComposition(context.Background(), config, descriptors, audit, memoryJetStreamOpener(connection, storeProbe, budgetProbe))
	if err != nil {
		t.Fatal(err)
	}
	if audit.called != 1 || !composition.Ready() || composition.NonceStore() == nil || composition.LeaseStore() == nil || composition.CapabilityBudget() == nil {
		t.Fatal("composition did not become exactly ready")
	}
	key, _ := primitives.NewSealingKey("staging-key", bytes.Repeat([]byte{1}, 32))
	service, err := composition.NewPrimitivesService(&runtimeKeyProvider{key: key}, time.Now)
	if err != nil || service.Epoch() != config.Epoch() {
		t.Fatalf("primitives service composition = %v", err)
	}
	if _, err := unix.Read(descriptor, make([]byte, 1)); err == nil {
		t.Fatal("NATS credential descriptor remained open")
	}
	if _, err := json.Marshal(composition); !errors.Is(err, ErrInvalid) || strings.Contains(composition.String(), "synthetic") {
		t.Fatal("composition exposed credential material")
	}
	budgetProbe.err.Store(true)
	if composition.Ready() {
		t.Fatal("dependency probe loss did not remove readiness")
	}
	budgetProbe.err.Store(false)
	backing := composition.credential
	if err := composition.Close(context.Background()); err != nil || connection.IsConnected() || !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Fatal("composition did not close and clear credential ownership")
	}
	if _, err := openJetStreamComposition(context.Background(), config, descriptors, audit, memoryJetStreamOpener(connection, storeProbe, budgetProbe)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("descriptor reuse = %v", err)
	}
}

func TestJetStreamCompositionRejectsEpochAndAuditAmbiguity(t *testing.T) {
	config := jetStreamTestConfig(t)
	for _, test := range []struct {
		name  string
		epoch uint64
		audit error
	}{
		{name: "wrong epoch", epoch: config.Epoch() + 1},
		{name: "audit unavailable", epoch: config.Epoch(), audit: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptors, _ := natsDescriptorFixture(t, []byte("synthetic-nats-credential"))
			connection := &connectionFixture{}
			connection.connected.Store(true)
			_, err := openJetStreamComposition(context.Background(), config, descriptors, &storageAuditFixture{err: test.audit}, memoryJetStreamOpener(connection, &storageProbeFixture{epoch: test.epoch}, &storageProbeFixture{epoch: config.Epoch()}))
			if !errors.Is(err, ErrUnavailable) || connection.IsConnected() {
				t.Fatalf("composition=%v connected=%v", err, connection.IsConnected())
			}
		})
	}
}

func TestJetStreamCompositionRejectsOversizedCredential(t *testing.T) {
	config := jetStreamTestConfig(t)
	descriptors, descriptor := natsDescriptorFixture(t, bytes.Repeat([]byte("x"), maxNATSCredentialBytes+1))
	connection := &connectionFixture{}
	probe := &storageProbeFixture{epoch: config.Epoch()}
	_, err := openJetStreamComposition(context.Background(), config, descriptors, &storageAuditFixture{}, memoryJetStreamOpener(connection, probe, probe))
	if !errors.Is(err, ErrUnavailable) || connection.IsConnected() {
		t.Fatalf("oversized credential error=%v connected=%v", err, connection.IsConnected())
	}
	if _, err := unix.Read(descriptor, make([]byte, 1)); err == nil {
		t.Fatal("oversized credential descriptor remained open")
	}
}

func memoryJetStreamOpener(connection *connectionFixture, probes ...storageProbe) jetStreamOpener {
	return func(_ context.Context, config *Config, credential []byte) (*jetStreamOpenResult, error) {
		if len(credential) == 0 {
			return nil, ErrUnavailable
		}
		store, _ := memory.New(config.MaxLeaseLifetime(), config.Epoch(), time.Now)
		budget, _ := memory.NewCapabilityBudget(config.CapabilityLimit(), config.CapabilityPendingTTL(), config.Epoch(), time.Now)
		return &jetStreamOpenResult{connection: connection, nonces: store, leases: store, budget: budget, probes: probes}, nil
	}
}

func jetStreamTestConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	value := configJSON{
		Profile: Profile, PublicBaseURI: "https://coordination.staging.example", PublicBind: "10.0.0.8:8443", OperationsBind: "127.0.0.1:9090",
		TLSCertificatePath: filepath.Join(dir, "tls.crt"), TLSPrivateKeyPath: filepath.Join(dir, "tls.key"), TLSTrustBundlePath: filepath.Join(dir, "ca.crt"),
		RegistrationPath: filepath.Join(dir, "registration.json"), RegistrationSignaturePath: filepath.Join(dir, "registration.sig"), ReplayDatabasePath: filepath.Join(dir, "replay.db"), AuditDatabasePath: filepath.Join(dir, "audit.db"),
		RegistrationKeyID: "key-1", RegistrationPublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		RequestDeadlineMS: 1000, MaxConcurrentRequests: 8, MaxReplayEntries: 128, MaxLeaseLifetimeMS: 60_000,
		NATSServerURI: "nats://127.0.0.1:4222", NATSConnectTimeoutMS: 1000, NATSRequestTimeoutMS: 1000, NATSReplicas: 1,
		NATSReplaySafetyWindowMS: 300_000, NATSRetentionMS: 3_600_000, CapabilityLimit: 8, CapabilityPendingTTLMS: 500, Epoch: 7,
	}
	raw, _ := json.Marshal(value)
	config, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func natsDescriptorFixture(t *testing.T, raw []byte) (*SecretDescriptors, int) {
	t.Helper()
	descriptor, err := unix.MemfdCreate("nats-credential-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if written, err := unix.Write(descriptor, raw); err != nil || written != len(raw) {
		t.Fatal(err)
	}
	if _, err := unix.Seek(descriptor, 0, 0); err != nil {
		t.Fatal(err)
	}
	descriptors, err := NewSecretDescriptors(descriptor, descriptor+1000)
	if err != nil {
		t.Fatal(err)
	}
	return descriptors, descriptor
}
