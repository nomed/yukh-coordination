package primitivesceremony

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCreatesClosedSyntheticCeremony(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"synthetic-tenant","principal_id":"synthetic-principal","root_key_id":"synthetic-root-v1","policy_key_id":"synthetic-policy-v1"}`)
	generator := Generator{Now: func() time.Time { return time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC) }}
	if err := generator.Generate(raw, output); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 11 {
		t.Fatalf("unexpected outputs: %v %d", err, len(entries))
	}
	for _, name := range []string{"root-private.pk8.pem", "leaf-private.pk8.pem", "policy-private.pk8.pem"} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0o400 {
			t.Fatalf("unsafe private output %s", name)
		}
	}
	receiptRaw, err := os.ReadFile(filepath.Join(output, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receiptRaw, []byte("synthetic.invalid")) || bytes.Contains(receiptRaw, []byte("synthetic-tenant")) {
		t.Fatal("receipt disclosed private config")
	}
	var receipt receiptJSON
	if json.Unmarshal(receiptRaw, &receipt) != nil || receipt.Profile != Profile || len(receipt.TrustBundleSHA256) != 64 || len(receipt.RegistrationTemplateSHA256) != 64 {
		t.Fatal("invalid receipt")
	}
	if err := Verify(output); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(output, "five-action-policy.json")
	if err := os.Chmod(policyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(output); err == nil {
		t.Fatal("verifier accepted changed policy")
	}
}

func TestGenerateRejectsUnsafeInputsWithoutPartialOutput(t *testing.T) {
	base := t.TempDir()
	tests := [][]byte{nil, []byte(`{}`), []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"bad/name","tenant_id":"t","principal_id":"p","root_key_id":"same","policy_key_id":"same"}`), []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"t","principal_id":"p","root_key_id":"r","policy_key_id":"k","unknown":true}`)}
	for index, raw := range tests {
		output := filepath.Join(base, string(rune('a'+index)))
		if err := os.Mkdir(output, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := (Generator{}).Generate(raw, output); err == nil {
			t.Fatal("accepted invalid config")
		}
		entries, _ := os.ReadDir(output)
		if len(entries) != 0 {
			t.Fatal("left partial output")
		}
	}
	unsafe := filepath.Join(base, "unsafe")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	valid := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"t","principal_id":"p","root_key_id":"r","policy_key_id":"k"}`)
	if err := (Generator{}).Generate(valid, unsafe); err == nil {
		t.Fatal("accepted unsafe output")
	}
}

func TestRotateLeafPreservesRootAndVerifiesExactIdentity(t *testing.T) {
	base := t.TempDir()
	initial := filepath.Join(base, "initial")
	if err := os.Mkdir(initial, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"t","principal_id":"p","root_key_id":"root-v1","policy_key_id":"policy-v1"}`)
	issued := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	if err := (Generator{Now: func() time.Time { return issued }}).Generate(raw, initial); err != nil {
		t.Fatal(err)
	}
	rotated := filepath.Join(base, "rotated")
	if err := os.Mkdir(rotated, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPrivate := filepath.Join(initial, "root-private.pk8.pem")
	rootCertificate := filepath.Join(initial, "root-cert.pem")
	if err := (Generator{Now: func() time.Time { return issued.Add(time.Hour) }}).RotateLeaf(raw, rootPrivate, rootCertificate, rotated); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(rotated)
	if err != nil || len(entries) != 3 {
		t.Fatalf("unexpected rotation outputs: %v %d", err, len(entries))
	}
	if err := VerifyLeafRotation(raw, rootCertificate, rotated); err != nil {
		t.Fatal(err)
	}
	wrong := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"other.invalid","tenant_id":"t","principal_id":"p","root_key_id":"root-v1","policy_key_id":"policy-v1"}`)
	if err := VerifyLeafRotation(wrong, rootCertificate, rotated); err == nil {
		t.Fatal("verified wrong identity")
	}
	if _, err := os.Stat(filepath.Join(rotated, "root-private.pk8.pem")); !os.IsNotExist(err) {
		t.Fatal("rotation copied root private key")
	}
}

func TestRotateLeafFailsClosed(t *testing.T) {
	base := t.TempDir()
	initial := filepath.Join(base, "initial")
	if err := os.Mkdir(initial, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"profile":"yukh-coordination/private-primitives-offline-ceremony-v1","server_name":"synthetic.invalid","tenant_id":"t","principal_id":"p","root_key_id":"root-v1","policy_key_id":"policy-v1"}`)
	issued := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	if err := (Generator{Now: func() time.Time { return issued }}).Generate(raw, initial); err != nil {
		t.Fatal(err)
	}
	rootPrivate := filepath.Join(initial, "root-private.pk8.pem")
	rootCertificate := filepath.Join(initial, "root-cert.pem")
	if err := os.Chmod(rootPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(base, "output")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := (Generator{Now: func() time.Time { return issued.Add(time.Hour) }}).RotateLeaf(raw, rootPrivate, rootCertificate, output); err == nil {
		t.Fatal("accepted unsafe root mode")
	}
	entries, _ := os.ReadDir(output)
	if len(entries) != 0 {
		t.Fatal("left partial rotation output")
	}
}
