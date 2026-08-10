package previewprofile

const (
	RunManifestProfile = "yukh-suite-preview-run-manifest/v1"
	TeardownTarget     = "complete_ephemeral_sandbox"
)

type ComponentBinding struct {
	ArtifactDigest string `json:"artifact_digest"`
	LogicalID      string `json:"logical_id"`
	ProfileVersion string `json:"profile_version"`
}

type Components struct {
	EffectAAudit      ComponentBinding `json:"effect_a_audit"`
	EffectAPrimitives ComponentBinding `json:"effect_a_primitives"`
	EffectBAudit      ComponentBinding `json:"effect_b_audit"`
	EffectBPrimitives ComponentBinding `json:"effect_b_primitives"`
	PreviewAuthority  ComponentBinding `json:"preview_authority"`
	ReceiptSigner     ComponentBinding `json:"receipt_signer"`
	Relay             ComponentBinding `json:"relay"`
	RelayAudit        ComponentBinding `json:"relay_audit"`
	RelayClientA      ComponentBinding `json:"relay_client_a"`
	RelayClientB      ComponentBinding `json:"relay_client_b"`
}

type ResourceBounds struct {
	MaxInflightOperations uint64 `json:"max_inflight_operations"`
	MaxMemoryMiB          uint64 `json:"max_memory_mib"`
	MaxProcesses          uint64 `json:"max_processes"`
	MaxStorageMiB         uint64 `json:"max_storage_mib"`
}

type RunManifest struct {
	Components              Components     `json:"components"`
	ConformanceCorpusDigest string         `json:"conformance_corpus_digest"`
	MaximumLifetimeSeconds  uint64         `json:"maximum_lifetime_seconds"`
	Profile                 string         `json:"profile"`
	ResourceBounds          ResourceBounds `json:"resource_bounds"`
	RunID                   string         `json:"run_id"`
	SourceCommit            string         `json:"source_commit"`
	SourceTreeDigest        string         `json:"source_tree_digest"`
	TeardownTarget          string         `json:"teardown_target"`
}

func ParseRunManifest(raw []byte) (RunManifest, error) {
	var value RunManifest
	if decodeCanonical(raw, &value, 32_768) != nil || ValidateRunManifest(value) != nil {
		return RunManifest{}, ErrInvalid
	}
	return value, nil
}

func CanonicalRunManifest(value RunManifest) ([]byte, error) {
	if ValidateRunManifest(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func ValidateRunManifest(value RunManifest) error {
	if value.Profile != RunManifestProfile ||
		!validIdentifier(value.RunID) ||
		!validCommit(value.SourceCommit) ||
		!validDigest(value.SourceTreeDigest) ||
		!validDigest(value.ConformanceCorpusDigest) ||
		value.MaximumLifetimeSeconds == 0 ||
		value.MaximumLifetimeSeconds > 4*60*60 ||
		value.TeardownTarget != TeardownTarget ||
		value.ResourceBounds.MaxProcesses == 0 ||
		value.ResourceBounds.MaxProcesses > 64 ||
		value.ResourceBounds.MaxMemoryMiB == 0 ||
		value.ResourceBounds.MaxMemoryMiB > 65_536 ||
		value.ResourceBounds.MaxStorageMiB == 0 ||
		value.ResourceBounds.MaxStorageMiB > 1_048_576 ||
		value.ResourceBounds.MaxInflightOperations == 0 ||
		value.ResourceBounds.MaxInflightOperations > 1_024 {
		return ErrInvalid
	}

	components := []ComponentBinding{
		value.Components.EffectAAudit,
		value.Components.EffectAPrimitives,
		value.Components.EffectBAudit,
		value.Components.EffectBPrimitives,
		value.Components.PreviewAuthority,
		value.Components.ReceiptSigner,
		value.Components.Relay,
		value.Components.RelayAudit,
		value.Components.RelayClientA,
		value.Components.RelayClientB,
	}
	seen := make(map[string]struct{}, len(components))
	for _, component := range components {
		if !validIdentifier(component.LogicalID) ||
			!validDigest(component.ArtifactDigest) ||
			!validIdentifier(component.ProfileVersion) {
			return ErrInvalid
		}
		if _, exists := seen[component.LogicalID]; exists {
			return ErrInvalid
		}
		seen[component.LogicalID] = struct{}{}
	}
	return nil
}
