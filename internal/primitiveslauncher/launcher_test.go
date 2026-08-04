package primitiveslauncher

import (
	"os"
	"path/filepath"
	"testing"
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
