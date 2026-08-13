package previewprofile

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type TeardownState string

const (
	StateRequested          TeardownState = "requested"
	StateAdmissionClosed    TeardownState = "admission_closed"
	StateEvidenceFrozen     TeardownState = "evidence_frozen"
	StateCredentialsRevoked TeardownState = "credentials_revoked"
	StateProcessesStopped   TeardownState = "processes_stopped"
	StateStorageRemoved     TeardownState = "storage_removed"
	StateNetworkRemoved     TeardownState = "network_removed"
	StateAbsenceVerified    TeardownState = "absence_verified"
	StateCompleted          TeardownState = "completed"
	StateIncomplete         TeardownState = "teardown_incomplete"
)

var ErrTeardownAlreadyRun = errors.New("preview profile: teardown may run only once")

type TeardownPorts struct {
	CloseAdmission    func(context.Context) error
	DrainInflight     func(context.Context) error
	FreezeEvidence    func(context.Context) (string, error)
	RevokeCredentials func(context.Context) error
	StopProcesses     func(context.Context) error
	RemoveStorage     func(context.Context) error
	RemoveNetwork     func(context.Context) error
	VerifyAbsence     func(context.Context) error
}

type TeardownStep struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

type TeardownReceipt struct {
	Profile           string         `json:"profile"`
	RunManifestDigest string         `json:"run_manifest_digest"`
	EvidenceDigest    string         `json:"evidence_digest,omitempty"`
	State             string         `json:"state"`
	Steps             []TeardownStep `json:"steps"`
}

type Teardown struct {
	mu             sync.RWMutex
	state          TeardownState
	run            bool
	manifestDigest string
	ports          TeardownPorts
}

func NewTeardown(manifestDigest string, ports TeardownPorts) (*Teardown, error) {
	if !digest(manifestDigest) || ports.CloseAdmission == nil || ports.DrainInflight == nil || ports.FreezeEvidence == nil || ports.RevokeCredentials == nil || ports.StopProcesses == nil || ports.RemoveStorage == nil || ports.RemoveNetwork == nil || ports.VerifyAbsence == nil {
		return nil, ErrInvalidManifest
	}
	return &Teardown{state: StateRequested, manifestDigest: manifestDigest, ports: ports}, nil
}

func (t *Teardown) State() TeardownState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state
}

// Run advances once through the fixed RFC-0025 teardown sequence. The first
// failed or ambiguous operation quarantines the remaining resources.
func (t *Teardown) Run(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidManifest
	}
	t.mu.Lock()
	if t.run {
		t.mu.Unlock()
		return nil, ErrTeardownAlreadyRun
	}
	t.run = true
	t.mu.Unlock()

	receipt := TeardownReceipt{Profile: "yukh-coordination/preview-teardown-receipt-v1", RunManifestDigest: t.manifestDigest}
	if err := t.ports.CloseAdmission(ctx); err != nil {
		receipt.Steps = append(receipt.Steps, TeardownStep{Name: "close-admission", Outcome: "failed"})
		return t.incomplete(receipt, err)
	}
	receipt.Steps = append(receipt.Steps, TeardownStep{Name: "close-admission", Outcome: "complete"})
	t.setState(StateAdmissionClosed)
	if err := t.ports.DrainInflight(ctx); err != nil {
		receipt.Steps = append(receipt.Steps, TeardownStep{Name: "drain-inflight", Outcome: "failed"})
		return t.incomplete(receipt, err)
	}
	receipt.Steps = append(receipt.Steps, TeardownStep{Name: "drain-inflight", Outcome: "complete"})
	evidenceDigest, err := t.ports.FreezeEvidence(ctx)
	if err != nil || !digest(evidenceDigest) {
		if err == nil {
			err = ErrInvalidManifest
		}
		receipt.Steps = append(receipt.Steps, TeardownStep{Name: "freeze-evidence", Outcome: "failed"})
		return t.incomplete(receipt, err)
	}
	receipt.EvidenceDigest = evidenceDigest
	t.setState(StateEvidenceFrozen)
	receipt.Steps = append(receipt.Steps, TeardownStep{Name: "freeze-evidence", Outcome: "complete"})

	remaining := []struct {
		name  string
		state TeardownState
		run   func(context.Context) error
	}{
		{"revoke-credentials", StateCredentialsRevoked, t.ports.RevokeCredentials},
		{"stop-services", StateProcessesStopped, t.ports.StopProcesses},
		{"remove-storage", StateStorageRemoved, t.ports.RemoveStorage},
		{"remove-network", StateNetworkRemoved, t.ports.RemoveNetwork},
		{"verify-absence", StateAbsenceVerified, t.ports.VerifyAbsence},
	}
	for _, operation := range remaining {
		if err := t.step(ctx, &receipt, operation.name, operation.state, operation.run); err != nil {
			return t.incomplete(receipt, err)
		}
	}
	t.setState(StateCompleted)
	receipt.State = "complete"
	return canonicalReceipt(receipt)
}

func (t *Teardown) step(ctx context.Context, receipt *TeardownReceipt, name string, state TeardownState, operation func(context.Context) error) error {
	if err := operation(ctx); err != nil {
		receipt.Steps = append(receipt.Steps, TeardownStep{Name: name, Outcome: "failed"})
		return err
	}
	receipt.Steps = append(receipt.Steps, TeardownStep{Name: name, Outcome: "complete"})
	t.setState(state)
	return nil
}

func (t *Teardown) incomplete(receipt TeardownReceipt, cause error) ([]byte, error) {
	t.setState(StateIncomplete)
	receipt.State = "teardown_incomplete"
	raw, encodingErr := canonicalReceipt(receipt)
	return raw, errors.Join(cause, encodingErr)
}

func (t *Teardown) setState(state TeardownState) {
	t.mu.Lock()
	t.state = state
	t.mu.Unlock()
}

func canonicalReceipt(receipt TeardownReceipt) ([]byte, error) {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func digest(value string) bool {
	return digestValue.MatchString(value)
}
