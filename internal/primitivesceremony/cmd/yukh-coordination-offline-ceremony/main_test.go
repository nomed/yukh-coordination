package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyInvocationIsReadOnly(t *testing.T) {
	base := t.TempDir()
	config := filepath.Join(base, "config.json")
	output := filepath.Join(base, "output")
	if err := os.WriteFile(config, []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"synthetic-tenant","principal_id":"synthetic-principal","root_key_id":"synthetic-root-v1","policy_key_id":"synthetic-policy-v1"}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{config, output}); err != nil {
		t.Fatalf("generate fixture: %v", err)
	}
	before := snapshot(t, output)
	if err := execute([]string{"verify", output}); err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	after := snapshot(t, output)
	if len(before) != len(after) {
		t.Fatalf("verify changed file count: %d != %d", len(before), len(after))
	}
	for name, expected := range before {
		actual, ok := after[name]
		if !ok || actual.mode != expected.mode || !bytes.Equal(actual.value, expected.value) {
			t.Fatalf("verify changed %s", name)
		}
	}
	policy := filepath.Join(output, "five-action-policy.json")
	if err := os.Chmod(policy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{"verify", output}); err == nil {
		t.Fatal("verified tampered output")
	}
}

func TestVerifyInvocationFailsClosed(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(base, "missing")
	if err := execute([]string{"verify", missing}); err == nil {
		t.Fatal("verified missing output")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("verify created missing output")
	}
	for _, arguments := range [][]string{nil, {"verify"}, {"verify", "relative"}, {"unknown", missing}, {"verify", missing, "extra"}} {
		if err := execute(arguments); err == nil {
			t.Fatalf("accepted arguments %#v", arguments)
		}
	}
}

func TestLeafRotationInvocation(t *testing.T) {
	base := t.TempDir()
	config := filepath.Join(base, "config.json")
	raw := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"t","principal_id":"p","root_key_id":"root-v1","policy_key_id":"policy-v1"}`)
	if err := os.WriteFile(config, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	initial := filepath.Join(base, "initial")
	if err := os.Mkdir(initial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{config, initial}); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(base, "rotated")
	if err := os.Mkdir(rotated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{"rotate-leaf", config, filepath.Join(initial, "root-private.pk8.pem"), filepath.Join(initial, "root-cert.pem"), rotated}); err != nil {
		t.Fatal(err)
	}
	if err := execute([]string{"verify-leaf", config, filepath.Join(initial, "root-cert.pem"), rotated}); err != nil {
		t.Fatal(err)
	}
}

type fileState struct {
	mode  os.FileMode
	value []byte
}

func snapshot(t *testing.T, directory string) map[string]fileState {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]fileState, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		value, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = fileState{mode: info.Mode(), value: value}
	}
	return result
}
