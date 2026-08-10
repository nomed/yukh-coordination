package schema_test

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	protocolschema "github.com/nomed/yukh-coordination/schema"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

type previewEffectFixture struct {
	Binding    string `json:"binding"`
	NonceScope string `json:"nonce_scope"`
	PreLease   string `json:"prelease"`
}

type previewFixture struct {
	EffectA        previewEffectFixture `json:"effect_a"`
	EffectB        previewEffectFixture `json:"effect_b"`
	PublicEvidence string               `json:"public_evidence"`
	RunManifest    string               `json:"run_manifest"`
}

func TestPreviewSchemasAcceptCanonicalConformanceVectors(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	err := fs.WalkDir(protocolschema.FS, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return walkErr
		}
		body, err := fs.ReadFile(protocolschema.FS, path)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(body, &document); err != nil {
			return err
		}
		return compiler.AddResource(document.(map[string]any)["$id"].(string), document)
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := fs.ReadFile(protocolschema.FS, "test-vectors/suite-preview-rfc-0025-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors previewFixture
	if json.Unmarshal(body, &vectors) != nil {
		t.Fatal("invalid RFC-0025 vectors")
	}

	cases := []struct {
		schema string
		raw    string
	}{
		{"suite-preview-run-manifest-1.schema.json", vectors.RunManifest},
		{"suite-preview-authority-1.schema.json", vectors.EffectA.NonceScope},
		{"suite-preview-authority-1.schema.json", vectors.EffectA.PreLease},
		{"suite-preview-authority-1.schema.json", vectors.EffectA.Binding},
		{"suite-preview-authority-1.schema.json", vectors.EffectB.NonceScope},
		{"suite-preview-authority-1.schema.json", vectors.EffectB.PreLease},
		{"suite-preview-authority-1.schema.json", vectors.EffectB.Binding},
		{"suite-preview-public-evidence-1.schema.json", vectors.PublicEvidence},
	}
	for _, test := range cases {
		compiled, err := compiler.Compile("https://yukh.dev/coordination/schema/" + test.schema)
		if err != nil {
			t.Fatalf("compile %s: %v", test.schema, err)
		}
		var value any
		if json.Unmarshal([]byte(test.raw), &value) != nil {
			t.Fatalf("invalid vector for %s", test.schema)
		}
		if err := compiled.Validate(value); err != nil {
			t.Fatalf("%s rejected vector: %v", test.schema, err)
		}
		value.(map[string]any)["credential"] = "forbidden"
		if compiled.Validate(value) == nil {
			t.Fatalf("%s accepted unknown credential", test.schema)
		}
	}
}
