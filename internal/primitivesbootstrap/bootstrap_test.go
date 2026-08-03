package primitivesbootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

const testRevision = "0123456789abcdef0123456789abcdef01234567"

func TestRunConsumesCredentialAndReturnsClosedReceipt(t *testing.T) {
	path := writeConfig(t, validConfig())
	descriptor, original := credentialFixture(t, []byte("synthetic-short-lived-bootstrap-credential"))
	var retained []byte
	receipt, err := run(context.Background(), path, descriptor, testRevision, func(_ context.Context, config *Config, credential []byte) error {
		if config.value.Epoch != 7 || string(credential) != "synthetic-short-lived-bootstrap-credential" {
			t.Fatal("closed bootstrap inputs changed")
		}
		retained = credential
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Read(original, make([]byte, 1)); err == nil {
		t.Fatal("original credential descriptor remained open")
	}
	if !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("credential backing was not cleared")
	}
	raw, err := receipt.Bytes()
	if err != nil || !bytes.HasSuffix(raw, []byte("\n")) || bytes.Contains(raw, []byte("127.0.0.1")) || bytes.Contains(raw, []byte("credential")) {
		t.Fatalf("unsafe receipt %q: %v", raw, err)
	}
	var decoded map[string]any
	if json.Unmarshal(bytes.TrimSpace(raw), &decoded) != nil || len(decoded) != 6 || decoded["outcome"] != "verified" || decoded["revision"] != testRevision {
		t.Fatalf("receipt schema drifted: %s", raw)
	}
	if _, err := run(context.Background(), path, descriptor, testRevision, func(context.Context, *Config, []byte) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("descriptor reuse = %v", err)
	}
}

func TestRunFailsClosedAndClearsCredential(t *testing.T) {
	path := writeConfig(t, validConfig())
	descriptor, _ := credentialFixture(t, []byte("private-provider-detail"))
	var retained []byte
	_, err := run(context.Background(), path, descriptor, testRevision, func(_ context.Context, _ *Config, credential []byte) error {
		retained = credential
		return errors.New("private endpoint and bucket detail")
	})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "endpoint") || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatalf("failure was not closed and cleared: %v", err)
	}
}

func TestConfigIsClosedAndBounded(t *testing.T) {
	valid := validConfig()
	if _, err := ParseConfig(valid); err != nil {
		t.Fatal(err)
	}
	invalid := [][]byte{
		bytes.Replace(valid, []byte(`"epoch":7`), []byte(`"epoch":0`), 1),
		bytes.Replace(valid, []byte(`nats://127.0.0.1:4222`), []byte(`tls://private.example:4222`), 1),
		bytes.Replace(valid, []byte(`"profile"`), []byte(`"unknown"`), 1),
		append(bytes.TrimSuffix(valid, []byte("}")), []byte(`,"epoch":8}`)...),
	}
	for index, raw := range invalid {
		if _, err := ParseConfig(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid config %d accepted: %v", index, err)
		}
	}
}

func TestReceiptRejectsUnrecordedRevision(t *testing.T) {
	config, err := ParseConfig(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{Schema: 1, Profile: Profile, Revision: "unrecorded", Epoch: 7, BucketProfile: config.profileDigest(), Outcome: "verified"}
	if _, err := receipt.Bytes(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unrecorded receipt = %v", err)
	}
}

func TestBootstrapCreatesAndThenVerifiesExactlyThreeDisposableBuckets(t *testing.T) {
	server := os.Getenv("YUKH_NATS_SERVER")
	if server == "" {
		t.Skip("YUKH_NATS_SERVER is not set")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	command := exec.Command(server, "-js", "-p", strconv.Itoa(port), "-sd", filepath.Join(t.TempDir(), "nats"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	uri := "nats://127.0.0.1:" + strconv.Itoa(port)
	var connection *nats.Conn
	for range 50 {
		connection, err = nats.Connect(uri, nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	raw := bytes.Replace(validConfig(), []byte("nats://127.0.0.1:4222"), []byte(uri), 1)
	config, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStores(context.Background(), config, connection); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapStores(context.Background(), config, connection); err != nil {
		t.Fatalf("verification rerun failed: %v", err)
	}
	legacy, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for name := range legacy.StreamNames() {
		names = append(names, name)
	}
	sort.Strings(names)
	expected := []string{"KV_YUKH_COORDINATION_CAPABILITY_BUDGET_V1", "KV_YUKH_COORDINATION_LEASES_V1", "KV_YUKH_COORDINATION_NONCES_V1"}
	if strings.Join(names, ",") != strings.Join(expected, ",") {
		t.Fatalf("bucket streams=%v", names)
	}
}

func validConfig() []byte {
	return []byte(`{"profile":"yukh-coordination/private-primitives-staging-bootstrap-v1","nats_server_uri":"nats://127.0.0.1:4222","nats_connect_timeout_ms":500,"nats_request_timeout_ms":1000,"nats_replicas":1,"nats_replay_safety_window_ms":120000,"nats_retention_ms":300001,"max_lease_lifetime_ms":60000,"capability_limit":4,"capability_pending_ttl_ms":1000,"epoch":7}`)
}

func writeConfig(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func credentialFixture(t *testing.T, value []byte) (*CredentialDescriptor, int) {
	t.Helper()
	fd, err := unix.MemfdCreate("bootstrap-credential", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, value); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err := CaptureCredentialDescriptor(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = descriptor.Close() })
	return descriptor, fd
}
