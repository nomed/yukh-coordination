package primitiveslauncher

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nomed/yukh-coordination/internal/primitivesstaging"
)

func TestPrepareClosedServiceAndBootstrapPlans(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "config.json")
	nats := filepath.Join(directory, "nats.secret")
	keyring := filepath.Join(directory, "keyring.secret")
	for _, path := range []string{config, nats, keyring} {
		if err := os.WriteFile(path, []byte("synthetic"), 0o400); err != nil {
			t.Fatal(err)
		}
	}

	service, err := Prepare([]string{"service", config, nats, keyring})
	if err != nil || service.executable != serviceExecutable || len(service.secrets) != 2 ||
		len(service.targets) != 2 || service.targets[0] != 3 || service.targets[1] != 4 {
		t.Fatal("service plan was not closed")
	}
	service.Close()

	bootstrap, err := Prepare([]string{"bootstrap", config, nats})
	if err != nil || bootstrap.executable != bootstrapExecutable || len(bootstrap.secrets) != 1 ||
		len(bootstrap.targets) != 1 || bootstrap.targets[0] != 3 {
		t.Fatal("bootstrap plan was not closed")
	}
	bootstrap.Close()
}

func TestPrepareRejectsArgumentsPathsAndUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "config.json")
	valid := filepath.Join(directory, "valid.secret")
	unsafe := filepath.Join(directory, "unsafe.secret")
	empty := filepath.Join(directory, "empty.secret")
	symlink := filepath.Join(directory, "link.secret")
	for path, fixture := range map[string]struct {
		value string
		mode  os.FileMode
	}{
		config: {value: "{}", mode: 0o400},
		valid:  {value: "synthetic", mode: 0o400},
		unsafe: {value: "synthetic", mode: 0o422},
		empty:  {value: "", mode: 0o400},
	} {
		if err := os.WriteFile(path, []byte(fixture.value), fixture.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(unsafe, 0o422); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}

	tests := [][]string{
		nil,
		{"unknown", config, valid},
		{"service", config, valid},
		{"bootstrap", config, valid, valid},
		{"bootstrap", "relative", valid},
		{"bootstrap", config, config},
		{"bootstrap", config, unsafe},
		{"bootstrap", config, empty},
		{"bootstrap", config, symlink},
		{"bootstrap", config, filepath.Join(directory, "missing")},
	}
	for _, arguments := range tests {
		if process, err := Prepare(arguments); err == nil {
			process.Close()
			t.Fatalf("accepted invalid arguments: %v", arguments)
		}
	}
}

func TestProcessCloseIsIdempotent(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "config.json")
	secret := filepath.Join(directory, "secret")
	if err := os.WriteFile(config, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("synthetic"), 0o400); err != nil {
		t.Fatal(err)
	}
	process, err := Prepare([]string{"bootstrap", config, secret})
	if err != nil {
		t.Fatal(err)
	}
	process.Close()
	process.Close()
	if err := process.Exec(); err == nil {
		t.Fatal("closed process remained executable")
	}
}

func TestPrepareKubernetesServiceRendersPodIPAtomically(t *testing.T) {
	directory := t.TempDir()
	runtimeRoot := filepath.Join(directory, "runtime")
	if err := os.Mkdir(runtimeRoot, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeRoot, 0o770); err != nil {
		t.Fatal(err)
	}
	template := filepath.Join(directory, "template.json")
	podIP := filepath.Join(directory, "pod-ip")
	privateRuntime := filepath.Join(runtimeRoot, "private")
	output := filepath.Join(privateRuntime, "rendered.json")
	nats := filepath.Join(directory, "nats.secret")
	keyring := filepath.Join(directory, "keyring.secret")
	value := map[string]any{
		"profile": primitivesstaging.Profile, "public_base_uri": "https://coordination.yukh.svc.cluster.local", "public_bind": primitivesstaging.PodIPPublicBindSlot, "operations_bind": "127.0.0.1:9090",
		"tls_certificate_path": "/private/tls.crt", "tls_private_key_path": "/private/tls.key", "tls_trust_bundle_path": "/private/ca.crt", "registration_path": "/private/registration.json", "registration_signature_path": "/private/registration.sig", "replay_database_path": "/state/replay.db", "audit_database_path": "/state/audit.db",
		"registration_key_id": "policy-v1", "registration_public_key": strings.Repeat("A", 43), "request_deadline_ms": 1000, "max_concurrent_requests": 8, "max_replay_entries": 1000, "max_lease_lifetime_ms": 60000,
		"nats_server_uri": "nats://127.0.0.1:4222", "nats_connect_timeout_ms": 1000, "nats_request_timeout_ms": 1000, "nats_replicas": 1, "nats_replay_safety_window_ms": 300000, "nats_retention_ms": 3600000, "capability_limit": 8, "capability_pending_ttl_ms": 500, "epoch": 1,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{template: raw, podIP: []byte("10.42.1.9\n"), nats: []byte("nats"), keyring: []byte("keyring")} {
		if err := os.WriteFile(path, contents, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	process, err := Prepare([]string{"service-kubernetes", template, podIP, output, nats, keyring})
	if err != nil || process.arguments[1] != output || len(process.secrets) != 2 {
		t.Fatal("Kubernetes service plan failed")
	}
	process.Close()
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatal("unsafe rendered config")
	}
	parentInfo, err := os.Stat(privateRuntime)
	if err != nil || parentInfo.Mode().Perm() != 0o700 {
		t.Fatal("private runtime directory was not closed")
	}
	rendered, _ := os.ReadFile(output)
	config, err := primitivesstaging.ParseConfig(rendered)
	if err != nil || config.PublicBind() != "10.42.1.9:8443" {
		t.Fatal("wrong rendered bind")
	}
	second, err := Prepare([]string{"service-kubernetes", template, podIP, output, nats, keyring})
	if err != nil {
		t.Fatal("exact restart was not idempotent")
	}
	second.Close()
}

func TestPrepareKubernetesServiceRejectsUnsafeRenderInputs(t *testing.T) {
	newFixture := func(t *testing.T) (map[string]string, []byte) {
		t.Helper()
		directory := t.TempDir()
		paths := map[string]string{
			"template": filepath.Join(directory, "template.json"),
			"podIP":    filepath.Join(directory, "pod-ip"),
			"output":   filepath.Join(directory, "rendered.json"),
			"nats":     filepath.Join(directory, "nats.secret"),
			"keyring":  filepath.Join(directory, "keyring.secret"),
		}
		value := map[string]any{
			"profile": primitivesstaging.Profile, "public_base_uri": "https://coordination.yukh.svc.cluster.local", "public_bind": primitivesstaging.PodIPPublicBindSlot, "operations_bind": "127.0.0.1:9090",
			"tls_certificate_path": "/private/tls.crt", "tls_private_key_path": "/private/tls.key", "tls_trust_bundle_path": "/private/ca.crt", "registration_path": "/private/registration.json", "registration_signature_path": "/private/registration.sig", "replay_database_path": "/state/replay.db", "audit_database_path": "/state/audit.db",
			"registration_key_id": "policy-v1", "registration_public_key": strings.Repeat("A", 43), "request_deadline_ms": 1000, "max_concurrent_requests": 8, "max_replay_entries": 1000, "max_lease_lifetime_ms": 60000,
			"nats_server_uri": "nats://127.0.0.1:4222", "nats_connect_timeout_ms": 1000, "nats_request_timeout_ms": 1000, "nats_replicas": 1, "nats_replay_safety_window_ms": 300000, "nats_retention_ms": 3600000, "capability_limit": 8, "capability_pending_ttl_ms": 500, "epoch": 1,
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for path, contents := range map[string][]byte{paths["template"]: raw, paths["podIP"]: []byte("10.42.1.9\n"), paths["nats"]: []byte("nats"), paths["keyring"]: []byte("keyring")} {
			if err := os.WriteFile(path, contents, 0o400); err != nil {
				t.Fatal(err)
			}
		}
		return paths, raw
	}
	arguments := func(paths map[string]string) []string {
		return []string{"service-kubernetes", paths["template"], paths["podIP"], paths["output"], paths["nats"], paths["keyring"]}
	}

	t.Run("non-private PodIP", func(t *testing.T) {
		paths, _ := newFixture(t)
		if err := os.Chmod(paths["podIP"], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths["podIP"], []byte("203.0.113.7\n"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths["podIP"], 0o400); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted non-private PodIP")
		}
	})

	t.Run("template without typed slot", func(t *testing.T) {
		paths, raw := newFixture(t)
		raw = bytes.Replace(raw, []byte(primitivesstaging.PodIPPublicBindSlot), []byte("10.42.1.8:8443"), 1)
		if err := os.Chmod(paths["template"], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths["template"], raw, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths["template"], 0o400); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted template without typed slot")
		}
	})

	t.Run("symlink PodIP", func(t *testing.T) {
		paths, _ := newFixture(t)
		target := filepath.Join(filepath.Dir(paths["podIP"]), "pod-ip-target")
		if err := os.Rename(paths["podIP"], target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, paths["podIP"]); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted symlink PodIP")
		}
	})

	t.Run("unsafe template mode", func(t *testing.T) {
		paths, _ := newFixture(t)
		if err := os.Chmod(paths["template"], 0o420); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted group-writable template")
		}
	})

	t.Run("different existing output", func(t *testing.T) {
		paths, _ := newFixture(t)
		if err := os.WriteFile(paths["output"], []byte("different"), 0o400); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("replaced different existing output")
		}
		contents, err := os.ReadFile(paths["output"])
		if err != nil || string(contents) != "different" {
			t.Fatal("changed existing output on failure")
		}
	})

	t.Run("partial existing output", func(t *testing.T) {
		paths, _ := newFixture(t)
		if err := os.WriteFile(paths["output"], []byte("{"), 0o400); err != nil {
			t.Fatal(err)
		}
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("replaced partial existing output")
		}
		contents, err := os.ReadFile(paths["output"])
		if err != nil || string(contents) != "{" {
			t.Fatal("changed partial output on failure")
		}
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(paths["output"]), ".yukh-rendered-config-*"))
		if err != nil || len(matches) != 0 {
			t.Fatal("left a temporary render output")
		}
	})

	t.Run("duplicate render path", func(t *testing.T) {
		paths, _ := newFixture(t)
		paths["output"] = paths["template"]
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted duplicate render path")
		}
	})

	t.Run("unsafe writable mount root", func(t *testing.T) {
		paths, _ := newFixture(t)
		mountRoot := filepath.Join(filepath.Dir(paths["output"]), "runtime")
		if err := os.Mkdir(mountRoot, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(mountRoot, 0o777); err != nil {
			t.Fatal(err)
		}
		paths["output"] = filepath.Join(mountRoot, "private", "rendered.json")
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted world-writable mount root")
		}
		if _, err := os.Lstat(filepath.Dir(paths["output"])); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("created private directory under unsafe mount root")
		}
	})

	t.Run("unsafe existing private directory", func(t *testing.T) {
		paths, _ := newFixture(t)
		private := filepath.Join(filepath.Dir(paths["output"]), "private")
		if err := os.Mkdir(private, 0o770); err != nil {
			t.Fatal(err)
		}
		paths["output"] = filepath.Join(private, "rendered.json")
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted group-writable private directory")
		}
	})

	t.Run("symlink private directory", func(t *testing.T) {
		paths, _ := newFixture(t)
		target := filepath.Join(filepath.Dir(paths["output"]), "target")
		private := filepath.Join(filepath.Dir(paths["output"]), "private")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, private); err != nil {
			t.Fatal(err)
		}
		paths["output"] = filepath.Join(private, "rendered.json")
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted symlink private directory")
		}
	})

	t.Run("ambiguous private directory", func(t *testing.T) {
		paths, _ := newFixture(t)
		private := filepath.Join(filepath.Dir(paths["output"]), "private")
		if err := os.Mkdir(private, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(private, "unexpected"), []byte("state"), 0o400); err != nil {
			t.Fatal(err)
		}
		paths["output"] = filepath.Join(private, "rendered.json")
		if process, err := Prepare(arguments(paths)); err == nil {
			process.Close()
			t.Fatal("accepted ambiguous private directory")
		}
	})
}
