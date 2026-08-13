package schema_test

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	protocolschema "github.com/nomed/yukh-coordination/schema"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestPreviewPublicSchemasAreClosed(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	for _, name := range []string{"preview-run-manifest-1.schema.json", "preview-public-evidence-1.schema.json", "preview-teardown-receipt-1.schema.json"} {
		body, err := fs.ReadFile(protocolschema.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if json.Unmarshal(body, &document) != nil || compiler.AddResource(document.(map[string]any)["$id"].(string), document) != nil {
			t.Fatalf("invalid schema %s", name)
		}
	}
	digest := "sha-256:" + strings.Repeat("a", 64)
	documents := map[string]map[string]any{
		"preview-run-manifest-1.schema.json": {
			"profile": "yukh-coordination/first-usable-preview-v1", "run_id": "qualification-01", "maximum_lifetime_seconds": 900,
			"artifacts": []any{
				map[string]any{"component": "relay", "image": "nomed/relay@sha256:" + strings.Repeat("a", 64)},
				map[string]any{"component": "primitives-effect-a", "image": "nomed/primitives@sha256:" + strings.Repeat("b", 64)},
				map[string]any{"component": "primitives-effect-b", "image": "nomed/primitives@sha256:" + strings.Repeat("b", 64)},
				map[string]any{"component": "preview-authority", "image": "nomed/authority@sha256:" + strings.Repeat("c", 64)},
				map[string]any{"component": "receipt-signer", "image": "nomed/signer@sha256:" + strings.Repeat("d", 64)},
			},
			"domains": []any{
				map[string]any{"role": "relay", "account": "relay-01", "storage": "relay-store"},
				map[string]any{"role": "effect-a", "account": "effect-a-01", "storage": "effect-a-store"},
				map[string]any{"role": "effect-b", "account": "effect-b-01", "storage": "effect-b-store"},
			},
		},
		"preview-public-evidence-1.schema.json": {
			"profile": "yukh-coordination/preview-public-evidence-v1", "run_manifest_digest": digest, "projection_digest": digest, "outcome": "qualified", "teardown_state": "complete",
		},
		"preview-teardown-receipt-1.schema.json": {
			"profile": "yukh-coordination/preview-teardown-receipt-v1", "run_manifest_digest": digest, "evidence_digest": digest, "state": "complete",
			"steps": []any{map[string]any{"name": "verify-absence", "outcome": "complete"}},
		},
	}
	for name, document := range documents {
		compiled, err := compiler.Compile("https://yukh.dev/coordination/schema/" + name)
		if err != nil || compiled.Validate(document) != nil {
			t.Fatalf("valid %s rejected: %v", name, err)
		}
		for _, forbidden := range []string{"credential", "nats_subject", "filesystem_path", "provider_text"} {
			document[forbidden] = "private"
			if compiled.Validate(document) == nil {
				t.Fatalf("%s accepted %s", name, forbidden)
			}
			delete(document, forbidden)
		}
	}
	teardown, err := compiler.Compile("https://yukh.dev/coordination/schema/preview-teardown-receipt-1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	incomplete := map[string]any{
		"profile": "yukh-coordination/preview-teardown-receipt-v1", "run_manifest_digest": digest,
		"state": "teardown_incomplete", "steps": []any{map[string]any{"name": "close-admission", "outcome": "failed"}},
	}
	if err := teardown.Validate(incomplete); err != nil {
		t.Fatalf("pre-evidence incomplete receipt rejected: %v", err)
	}
}
