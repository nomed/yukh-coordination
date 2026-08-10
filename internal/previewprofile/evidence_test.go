package previewprofile_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nomed/yukh-coordination/internal/previewprofile"
)

func TestPublicEvidenceStrictAllowlist(t *testing.T) {
	vectors := loadFixture(t)
	evidence, err := previewprofile.ParsePublicEvidence([]byte(vectors.PublicEvidence))
	if err != nil {
		t.Fatalf("public evidence rejected: %v", err)
	}
	canonical, err := previewprofile.CanonicalPublicEvidence(evidence)
	if err != nil || string(canonical) != vectors.PublicEvidence {
		t.Fatal("public evidence canonical bytes changed")
	}
	paths := previewprofile.PublicEvidenceAllowedPaths()
	if len(paths) == 0 {
		t.Fatal("public evidence allowlist is empty")
	}
	for index := 1; index < len(paths); index++ {
		if paths[index-1] >= paths[index] {
			t.Fatal("public evidence allowlist is not closed and sorted")
		}
	}
}

func TestPublicEvidenceRejectsForbiddenMaterial(t *testing.T) {
	vectors := loadFixture(t)
	var base map[string]any
	if json.Unmarshal([]byte(vectors.PublicEvidence), &base) != nil {
		t.Fatal("invalid public evidence fixture")
	}
	rawDigest := strings.Repeat("a", 64)
	adversarial := map[string]func(map[string]any){
		"token":       func(value map[string]any) { value["token"] = "secret" },
		"private key": func(value map[string]any) { value["private_key"] = "secret" },
		"raw nonce scope": func(value map[string]any) {
			value["effects"].([]any)[0].(map[string]any)["nonce_scope_binding"] = rawDigest
		},
		"raw nonce value": func(value map[string]any) {
			value["effects"].([]any)[0].(map[string]any)["value_digest"] = rawDigest
		},
		"lease capability": func(value map[string]any) {
			value["effects"].([]any)[0].(map[string]any)["lease_capability"] = "capability-secret"
		},
		"lease material in outcome": func(value map[string]any) {
			value["effects"].([]any)[0].(map[string]any)["lease_outcome"] = "lease-secret"
		},
		"binding material": func(value map[string]any) {
			value["contracts"].([]any)[0].(map[string]any)["version"] = "binding-secret"
		},
		"approval envelope": func(value map[string]any) {
			value["relay"].(map[string]any)["approval"] = map[string]any{"nonce": "secret"}
		},
		"provider response": func(value map[string]any) {
			value["relay"].(map[string]any)["provider_response"] = "private"
		},
		"case alias": func(value map[string]any) { value["Token"] = "secret" },
	}
	for name, mutate := range adversarial {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var changed map[string]any
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("cannot clone fixture")
			}
			mutate(changed)
			if _, err := previewprofile.ParsePublicEvidence(canonicalJSON(t, changed)); !errors.Is(err, previewprofile.ErrInvalid) {
				t.Fatalf("forbidden public evidence accepted: %v", err)
			}
		})
	}
}

func TestPublicEvidenceChangedScopeInvariant(t *testing.T) {
	vectors := loadFixture(t)
	evidence, err := previewprofile.ParsePublicEvidence([]byte(vectors.PublicEvidence))
	if err != nil {
		t.Fatal(err)
	}
	evidence.Effects[1].NonceConsumeCalls = 1
	evidence.Effects[1].NonceOutcome = "consumed"
	if previewprofile.ValidatePublicEvidence(evidence) == nil {
		t.Fatal("changed-scope evidence claimed a consume call")
	}
}
