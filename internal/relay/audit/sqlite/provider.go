package sqlite

import (
	"context"
	"crypto/ed25519"
	"reflect"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

// OperationalProvider is the runtime-facing identity Auditor adapter. Its
// readiness is the strong RFC-0011 operational gate, not structural DB health.
type OperationalProvider struct {
	ledger    *Ledger
	authority ed25519.PublicKey
	policy    audit.ReadinessPolicy
	signer    audit.CheckpointSigner
	probe     audit.SignerReadiness
	witness   audit.WitnessVerifier
	now       func() time.Time
}

func NewOperationalProvider(ledger *Ledger, authority ed25519.PublicKey, policy audit.ReadinessPolicy, signer audit.CheckpointSigner, probe audit.SignerReadiness, witness audit.WitnessVerifier, now func() time.Time) (*OperationalProvider, error) {
	if ledger == nil || len(authority) != ed25519.PublicKeySize || nilPort(signer) || nilPort(probe) || now == nil {
		return nil, audit.ErrUnavailable
	}
	provider := &OperationalProvider{ledger: ledger, authority: append(ed25519.PublicKey(nil), authority...), policy: policy, signer: signer, probe: probe, witness: witness, now: now}
	if policy.RequireWitness && nilPort(witness) {
		return nil, audit.ErrUnavailable
	}
	return provider, nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func (p *OperationalProvider) Record(ctx context.Context, record identity.AuditRecord) (string, error) {
	if p == nil {
		return "", audit.ErrUnavailable
	}
	return p.ledger.Record(ctx, record)
}

func (p *OperationalProvider) Ready(ctx context.Context) error {
	if p == nil {
		return audit.ErrUnavailable
	}
	return p.ledger.OperationalReady(ctx, p.now().UTC().Truncate(time.Millisecond), p.authority, p.policy, p.signer, p.probe, p.witness)
}
