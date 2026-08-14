package previewruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func TestPreviewChannelAuthorizerAndSignerAreClosed(t *testing.T) {
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	channel, err := previewChannel(validator)
	if err != nil {
		t.Fatal(err)
	}
	if channel.Key != (relay.ChannelKey{TenantID: PreviewTenantID, ChannelID: PreviewChannelID, TranscriptEpoch: PreviewEpoch}) || channel.URI != PreviewChannelURI {
		t.Fatalf("channel=%+v", channel)
	}
	identity := httpapi.Identity{TenantID: PreviewTenantID, PrincipalID: "principal:agent-a", ParticipantInstanceID: "019c6f5b-7c00-7000-8000-000000000701", SessionEpoch: 1}
	decision, err := (previewAuthorizer{}).Authorize(context.Background(), httpapi.AccessRequest{Identity: identity, Channel: channel.Key, Action: httpapi.ActionPublish})
	if err != nil || !decision.Allowed || len(decision.CanonicalBinding) == 0 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	wrong := channel.Key
	wrong.ChannelID = "channel:other"
	if _, err := (previewAuthorizer{}).Authorize(context.Background(), httpapi.AccessRequest{Identity: identity, Channel: wrong, Action: httpapi.ActionPublish}); err == nil {
		t.Fatal("wrong channel authorized")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	preimage := []byte("receipt-preimage")
	signature, err := (previewSigner{privateKey: privateKey}).Sign(context.Background(), relay.AcceptedRecord{UnsignedReceiptPreimage: preimage})
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), preimage, signature) {
		t.Fatalf("signature invalid: %v", err)
	}
}

func TestCoordinatorEndpointsRejectAmbientTargets(t *testing.T) {
	for _, value := range []string{"nats://127.0.0.1:4222", "nats://nats:4222"} {
		if !localNATSURL(value) {
			t.Fatalf("local NATS rejected: %s", value)
		}
	}
	for _, value := range []string{"nats://example.com:4222", "nats://127.0.0.1", "http://127.0.0.1:4222", "nats://user@nats:4222"} {
		if localNATSURL(value) {
			t.Fatalf("unsafe NATS accepted: %s", value)
		}
	}
	if !httpsBase("https://127.0.0.1:7443") || httpsBase("http://127.0.0.1:7443") || httpsBase("https://127.0.0.1:7443/path") {
		t.Fatal("HTTPS base validation failed")
	}
}

func TestCoordinatorStartsAgainstLocalJetStream(t *testing.T) {
	binary := os.Getenv("YUKH_NATS_SERVER")
	if binary == "" {
		t.Skip("YUKH_NATS_SERVER is not configured")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	command := exec.Command(binary, "-js", "-p", fmt.Sprint(port), "-sd", filepath.Join(t.TempDir(), "nats"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var coordinator *Coordinator
	for ctx.Err() == nil {
		coordinator, err = NewCoordinator(ctx, CoordinatorConfig{NATSURL: fmt.Sprintf("nats://127.0.0.1:%d", port), PublicBaseURI: "https://127.0.0.1:7443", Listener: listener, Authority: NewAuthority()})
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	runContext, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(runContext) }()
	select {
	case <-coordinator.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("coordinator did not become ready")
	}
	if coordinator.ReceiptPublicKey() == "" {
		t.Fatal("receipt key unavailable")
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
