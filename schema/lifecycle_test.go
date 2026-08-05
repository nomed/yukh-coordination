package schema_test

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	protocolschema "github.com/nomed/yukh-coordination/schema"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

func TestLifecycleSchemasCompileAndAcceptCanonicalVectors(t *testing.T) {
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
		identifier := document.(map[string]any)["$id"].(string)
		return compiler.AddResource(identifier, document)
	})
	if err != nil {
		t.Fatal(err)
	}

	vectorsBody, err := fs.ReadFile(protocolschema.FS, "test-vectors/transcript-lifecycle-0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]string
	if err := json.Unmarshal(vectorsBody, &vectors); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"policy":           "transcript-lifecycle-policy-0.1.schema.json",
		"intent":           "transcript-lifecycle-intent-0.1.schema.json",
		"marker":           "transcript-lifecycle-marker-0.1.schema.json",
		"receipt_preimage": "transcript-lifecycle-receipt-preimage-0.1.schema.json",
	}
	for vector, name := range cases {
		compiled, err := compiler.Compile("https://yukh.dev/coordination/schema/" + name)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		var value any
		if err := json.Unmarshal([]byte(vectors[vector]), &value); err != nil || compiled.Validate(value) != nil {
			t.Fatalf("vector %s rejected: %v", vector, err)
		}
		object := value.(map[string]any)
		object["provider_error"] = "private detail"
		if compiled.Validate(object) == nil {
			t.Fatalf("schema %s accepted unknown provider detail", name)
		}
	}
}

func TestBackupCompletionSchemasAcceptIndependentVectors(t *testing.T) {
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
	body, err := fs.ReadFile(protocolschema.FS, "test-vectors/transcript-backup-completion-0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors map[string]string
	if json.Unmarshal(body, &vectors) != nil {
		t.Fatal("invalid vectors")
	}
	cases := map[string]string{"obligation": "transcript-backup-obligation-0.1.schema.json", "custodian_receipt": "transcript-backup-custodian-receipt-0.1.schema.json", "completion_evidence": "transcript-lifecycle-completion-evidence-0.1.schema.json", "recovery": "transcript-lifecycle-backup-recovery-0.1.schema.json"}
	for vector, name := range cases {
		compiled, err := compiler.Compile("https://yukh.dev/coordination/schema/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if json.Unmarshal([]byte(vectors[vector]), &value) != nil || compiled.Validate(value) != nil {
			t.Fatalf("%s rejected", vector)
		}
		value.(map[string]any)["provider_response"] = "private"
		if compiled.Validate(value) == nil {
			t.Fatalf("%s accepted provider detail", name)
		}
	}
}
