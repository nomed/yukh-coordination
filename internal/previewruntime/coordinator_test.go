package previewruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
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

func TestConfigAndSupervisorExposeOnlyBoundMaterial(t *testing.T) {
	directory := t.TempDir()
	certificate := filepath.Join(directory, "tls.crt")
	privateKey := filepath.Join(directory, "tls.key")
	tokenPath := filepath.Join(directory, "supervisor.token")
	tokenBytes := make([]byte, 32)
	tokenBytes[0] = 1
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	for path, value := range map[string]string{certificate: "certificate", privateKey: "private-key", tokenPath: token} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "coordinator.json")
	configRaw, _ := json.Marshal(map[string]any{"profile": ConfigProfile, "public_base_uri": "https://127.0.0.1:7443", "public_bind": "0.0.0.0:7443", "supervisor_bind": "0.0.0.0:7444", "nats_url": "nats://nats:4222", "tls_certificate": certificate, "tls_private_key": privateKey, "supervisor_token": tokenPath})
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(configPath); err != nil {
		t.Fatal(err)
	}
	authority := NewAuthority()
	receiptBytes := make([]byte, 32)
	receiptBytes[0] = 2
	receiptKey := base64.RawURLEncoding.EncodeToString(receiptBytes)
	supervisor, err := NewSupervisor(authority, token, receiptKey)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x, y := key.PublicKey.X.FillBytes(make([]byte, 32)), key.PublicKey.Y.FillBytes(make([]byte, 32))
	thumbprint := mustThumbprint(t, key)
	body, _ := json.Marshal(map[string]any{"crv": "P-256", "dpop_thumbprint": base64.RawURLEncoding.EncodeToString(thumbprint[:]), "kty": "EC", "schema": 1, "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)})
	body, _ = jsoncanonicalizer.Transform(body)
	request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:7444/local-preview/v1/external-token/agent-a", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	supervisor.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	metadata := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:7444/local-preview/v1/config", nil)
	metadata.Header.Set("Authorization", "Bearer "+token)
	metadataResponse := httptest.NewRecorder()
	supervisor.ServeHTTP(metadataResponse, metadata)
	if metadataResponse.Code != http.StatusOK || !bytes.Contains(metadataResponse.Body.Bytes(), []byte(receiptKey)) {
		t.Fatalf("metadata status=%d body=%s", metadataResponse.Code, metadataResponse.Body.String())
	}
}
