package previewprofile

import (
	"encoding/json"
	"sort"
)

const (
	PublicEvidenceProfile     = "yukh-suite-preview-public-evidence/v1"
	IncompleteTeardownReceipt = "absent:teardown-incomplete"
)

type ArtifactClass string

const (
	ArtifactSource     ArtifactClass = "source"
	ArtifactTree       ArtifactClass = "tree"
	ArtifactBinary     ArtifactClass = "artifact"
	ArtifactSBOM       ArtifactClass = "sbom"
	ArtifactProvenance ArtifactClass = "provenance"
)

type PublicArtifact struct {
	Class     ArtifactClass `json:"class"`
	Component string        `json:"component"`
	Digest    string        `json:"digest"`
}

type ContractEvidence struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type EffectDigests struct {
	EffectA string `json:"effect_a"`
	EffectB string `json:"effect_b"`
}

type RelayEvidence struct {
	AuditCheckpointDigest   string `json:"audit_checkpoint_digest"`
	AuditCheckpointOutcome  string `json:"audit_checkpoint_outcome"`
	ReceiptChainDigest      string `json:"receipt_chain_digest"`
	ReceiptChainOutcome     string `json:"receipt_chain_outcome"`
	ReplayProjectionDigest  string `json:"replay_projection_digest"`
	ReplayProjectionOutcome string `json:"replay_projection_outcome"`
}

type EffectEvidence struct {
	CompletionOutcome   string `json:"completion_outcome"`
	DenialOutcome       string `json:"denial_outcome"`
	Effect              string `json:"effect"`
	LeaseOutcome        string `json:"lease_outcome"`
	NonceConsumeCalls   uint8  `json:"nonce_consume_calls"`
	NonceOutcome        string `json:"nonce_outcome"`
	NonceScopeBinding   string `json:"nonce_scope_binding"`
	VerificationOutcome string `json:"verification_outcome"`
}

type ResourceEvidence struct {
	AdmissionOutcome string `json:"admission_outcome"`
	BoundsOutcome    string `json:"bounds_outcome"`
	CleanupOutcome   string `json:"cleanup_outcome"`
}

type TeardownEvidence struct {
	ReceiptDigest string        `json:"receipt_digest"`
	State         TeardownState `json:"state"`
}

type PublicEvidence struct {
	Artifacts                 []PublicArtifact   `json:"artifacts"`
	CompatibilityMatrixDigest string             `json:"compatibility_matrix_digest"`
	Contracts                 []ContractEvidence `json:"contracts"`
	Effects                   []EffectEvidence   `json:"effects"`
	KnownLimitations          []string           `json:"known_limitations"`
	OperationSetDigests       EffectDigests      `json:"operation_set_digests"`
	Profile                   string             `json:"profile"`
	Relay                     RelayEvidence      `json:"relay"`
	ResidualRisks             []string           `json:"residual_risks"`
	ResourceOutcomes          ResourceEvidence   `json:"resource_outcomes"`
	RunManifestDigest         string             `json:"run_manifest_digest"`
	Teardown                  TeardownEvidence   `json:"teardown"`
}

var publicEvidenceAllowedPaths = map[string]struct{}{
	"artifacts": {}, "artifacts[]": {}, "artifacts[].class": {},
	"artifacts[].component": {}, "artifacts[].digest": {},
	"compatibility_matrix_digest": {},
	"contracts":                   {}, "contracts[]": {}, "contracts[].name": {}, "contracts[].version": {},
	"effects": {}, "effects[]": {}, "effects[].completion_outcome": {},
	"effects[].denial_outcome": {}, "effects[].effect": {}, "effects[].lease_outcome": {},
	"effects[].nonce_consume_calls": {}, "effects[].nonce_outcome": {},
	"effects[].nonce_scope_binding": {}, "effects[].verification_outcome": {},
	"known_limitations": {}, "known_limitations[]": {},
	"operation_set_digests": {}, "operation_set_digests.effect_a": {},
	"operation_set_digests.effect_b": {}, "profile": {},
	"relay": {}, "relay.audit_checkpoint_digest": {}, "relay.audit_checkpoint_outcome": {},
	"relay.receipt_chain_digest": {}, "relay.receipt_chain_outcome": {},
	"relay.replay_projection_digest": {}, "relay.replay_projection_outcome": {},
	"residual_risks": {}, "residual_risks[]": {},
	"resource_outcomes": {}, "resource_outcomes.admission_outcome": {},
	"resource_outcomes.bounds_outcome": {}, "resource_outcomes.cleanup_outcome": {},
	"run_manifest_digest": {}, "teardown": {}, "teardown.receipt_digest": {},
	"teardown.state": {},
}

func PublicEvidenceAllowedPaths() []string {
	result := make([]string, 0, len(publicEvidenceAllowedPaths))
	for path := range publicEvidenceAllowedPaths {
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func ParsePublicEvidence(raw []byte) (PublicEvidence, error) {
	if validateEvidencePaths(raw) != nil {
		return PublicEvidence{}, ErrInvalid
	}
	var value PublicEvidence
	if decodeCanonical(raw, &value, 65_536) != nil || ValidatePublicEvidence(value) != nil {
		return PublicEvidence{}, ErrInvalid
	}
	return value, nil
}

func CanonicalPublicEvidence(value PublicEvidence) ([]byte, error) {
	if ValidatePublicEvidence(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func ValidatePublicEvidence(value PublicEvidence) error {
	if value.Profile != PublicEvidenceProfile ||
		!validDigest(value.CompatibilityMatrixDigest) ||
		!validDigest(value.OperationSetDigests.EffectA) ||
		!validDigest(value.OperationSetDigests.EffectB) ||
		!validDigest(value.RunManifestDigest) ||
		len(value.Artifacts) == 0 || len(value.Artifacts) > 64 ||
		len(value.Contracts) == 0 || len(value.Contracts) > 32 ||
		len(value.Effects) != 2 {
		return ErrInvalid
	}
	artifactKeys := map[string]struct{}{}
	for _, artifact := range value.Artifacts {
		if !validArtifactClass(artifact.Class) || !validComponentLabel(artifact.Component) ||
			!validDigest(artifact.Digest) {
			return ErrInvalid
		}
		key := string(artifact.Class) + "\x00" + artifact.Component
		if _, exists := artifactKeys[key]; exists {
			return ErrInvalid
		}
		artifactKeys[key] = struct{}{}
	}
	contractKeys := map[string]struct{}{}
	for _, contract := range value.Contracts {
		if !validContractVersion(contract.Name, contract.Version) {
			return ErrInvalid
		}
		if _, exists := contractKeys[contract.Name]; exists {
			return ErrInvalid
		}
		contractKeys[contract.Name] = struct{}{}
	}
	if !validEffectEvidence(value.Effects[0], "effect_a") ||
		!validEffectEvidence(value.Effects[1], "effect_b") ||
		!validRelayEvidence(value.Relay) ||
		!oneOf(value.ResourceOutcomes.AdmissionOutcome, "open", "closed", "expired", "failed") ||
		!oneOf(value.ResourceOutcomes.BoundsOutcome, "within_bounds", "exceeded", "unknown") ||
		!oneOf(value.ResourceOutcomes.CleanupOutcome, "not_started", "bounded", "failed", "unknown") ||
		!validClosedValues(value.KnownLimitations, 1, 8,
			"no_runtime", "no_network", "no_provider", "no_credentials",
			"synthetic_only", "logical_isolation_only") ||
		!validClosedValues(value.ResidualRisks, 1, 8,
			"host_compromise", "consumer_defect", "operator_evidence_sensitive",
			"no_retained_service_recovery") {
		return ErrInvalid
	}
	if value.Teardown.State != TeardownIncomplete && value.Teardown.State != TeardownCompleted {
		return ErrInvalid
	}
	if value.Teardown.State == TeardownCompleted && !validDigest(value.Teardown.ReceiptDigest) {
		return ErrInvalid
	}
	if value.Teardown.State == TeardownIncomplete && value.Teardown.ReceiptDigest != IncompleteTeardownReceipt {
		return ErrInvalid
	}
	return nil
}

func validateEvidencePaths(raw []byte) error {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ErrInvalid
	}
	if walkEvidencePath(value, "") {
		return nil
	}
	return ErrInvalid
}

func walkEvidencePath(value any, parent string) bool {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			path := key
			if parent != "" {
				path = parent + "." + key
			}
			if _, allowed := publicEvidenceAllowedPaths[path]; !allowed ||
				!walkEvidencePath(child, path) {
				return false
			}
		}
	case []any:
		path := parent + "[]"
		if _, allowed := publicEvidenceAllowedPaths[path]; !allowed {
			return false
		}
		for _, child := range current {
			if !walkEvidencePath(child, path) {
				return false
			}
		}
	}
	return true
}

func validArtifactClass(value ArtifactClass) bool {
	return value == ArtifactSource || value == ArtifactTree || value == ArtifactBinary ||
		value == ArtifactSBOM || value == ArtifactProvenance
}

func validComponentLabel(value string) bool {
	return oneOf(value, "coordination", "relay", "relay_client", "preview_authority",
		"receipt_signer", "effect_a_primitives", "effect_b_primitives")
}

func validContractVersion(name, version string) bool {
	switch name {
	case "run_manifest", "effect_a_binding", "effect_b_binding", "public_evidence", "teardown":
		return version == "v1"
	case "rfc_0015_nonce":
		return version == "rfc-0015"
	case "rfc_0016_lease":
		return version == "rfc-0016"
	default:
		return false
	}
}

func validEffectEvidence(value EffectEvidence, effect string) bool {
	if value.Effect != effect ||
		value.NonceConsumeCalls > 1 ||
		!oneOf(value.NonceScopeBinding, "matched", "changed_scope_denied", "failed") ||
		!oneOf(value.NonceOutcome, "not_called", "consumed", "replayed", "denied") ||
		!oneOf(value.LeaseOutcome, "not_requested", "acquired", "conflict", "lost", "stale", "expired", "released") ||
		!oneOf(value.DenialOutcome, "none", "pre_effect_denied", "changed_scope_denied", "cross_effect_reuse_denied", "completion_unknown") ||
		!oneOf(value.VerificationOutcome, "not_attempted", "verified", "failed", "unknown") ||
		!oneOf(value.CompletionOutcome, "not_attempted", "verified", "failed_without_effect", "completion_unknown") {
		return false
	}
	if value.NonceScopeBinding == "changed_scope_denied" {
		return value.NonceConsumeCalls == 0 &&
			value.NonceOutcome != "consumed" &&
			value.DenialOutcome == "changed_scope_denied" &&
			value.VerificationOutcome == "not_attempted" &&
			value.CompletionOutcome == "not_attempted"
	}
	return true
}

func validRelayEvidence(value RelayEvidence) bool {
	return validDigest(value.AuditCheckpointDigest) &&
		validDigest(value.ReceiptChainDigest) &&
		validDigest(value.ReplayProjectionDigest) &&
		oneOf(value.AuditCheckpointOutcome, "verified", "failed", "unavailable") &&
		oneOf(value.ReceiptChainOutcome, "verified", "failed") &&
		oneOf(value.ReplayProjectionOutcome, "verified", "failed", "diverged")
}

func validClosedValues(values []string, minimum, maximum int, allowed ...string) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if !oneOf(value, allowed...) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
