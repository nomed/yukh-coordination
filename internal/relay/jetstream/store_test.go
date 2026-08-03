package jetstream

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
)

func TestTenantSubjectDoesNotExposeTenant(t *testing.T) {
	subject, err := TenantSubject("tenant:customer-sensitive")
	if err != nil {
		t.Fatal(err)
	}
	if subject == "" || subject == "yukh.coordination.v1.tenant.tenant:customer-sensitive.log" {
		t.Fatalf("unsafe tenant subject %q", subject)
	}
	again, _ := TenantSubject("tenant:customer-sensitive")
	if subject != again {
		t.Fatal("tenant subject is not deterministic")
	}
}

func TestOpenBootstrapsAndRejectsMismatchedRealStream(t *testing.T) {
	server := os.Getenv("YUKH_NATS_SERVER")
	if server == "" {
		t.Skip("YUKH_NATS_SERVER is not set")
	}
	port := "14222"
	command := exec.Command(server, "-js", "-p", port, "-sd", filepath.Join(t.TempDir(), "nats"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	var connection *nats.Conn
	var err error
	for range 50 {
		connection, err = nats.Connect("nats://127.0.0.1:"+port, nats.Timeout(100*time.Millisecond))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Open(ctx, connection, Config{Replicas: 1, Bootstrap: true}); err != nil {
		t.Fatal(err)
	}
	js, _ := natsjs.New(connection)
	if _, err := js.Stream(ctx, StreamName); err != nil {
		t.Fatal(err)
	}
	config := ExpectedStreamConfig(1)
	config.MaxMsgSize--
	if _, err := js.UpdateStream(ctx, config); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, connection, Config{Replicas: 1}); err == nil {
		t.Fatal("mismatched stream accepted")
	}
}
