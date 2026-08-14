package clientcli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"golang.org/x/sys/unix"
)

func TestExecutableComposesClosedLocalCustody(t *testing.T) {
	directory := physicalTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "client.json")
	databasePath := filepath.Join(directory, "custody.db")
	config := map[string]any{
		"schema": 1, "profile": "default", "base_uri": "https://coord.example",
		"channel_id": "channel:test", "channel_uri": "https://coord.example/channels/test",
		"transcript_epoch": 1, "page_limit": 100, "max_records": 1000,
		"source_uri": "https://client.example/session", "participant": map[string]any{"id": "agent:test", "kind": "agent"},
		"custody_database": databasePath,
		"receipt_keys":     []map[string]any{{"key_id": "key-1", "public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}},
	}
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	read, write, _ := os.Pipe()
	_, _ = write.Write(make([]byte, 32))
	_ = write.Close()
	rootDescriptor, _ := unix.Dup(int(read.Fd()))
	args := []string{"--config", configPath, "--root-key-fd", strconv.Itoa(rootDescriptor), "session", "join"}
	var stdout bytes.Buffer
	status := (Executable{}).Run(context.Background(), args, bytes.NewBufferString(`{}`), &stdout)
	runtime.KeepAlive(read)
	if status != 2 || !bytes.Contains(stdout.Bytes(), []byte(`"command":"session join"`)) {
		t.Fatalf("status=%d output=%s", status, stdout.Bytes())
	}
	if info, err := os.Stat(databasePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database info=%v err=%v", info, err)
	}
}

func TestExecutableRejectsMissingProcessConfiguration(t *testing.T) {
	var stdout bytes.Buffer
	if status := (Executable{}).Run(context.Background(), []string{"session", "join"}, bytes.NewReader(nil), &stdout); status != 2 {
		t.Fatalf("status=%d output=%s", status, stdout.Bytes())
	}
}

func TestExecutableBootstrapsThroughSupervisorAndPersistsSession(t *testing.T) {
	directory := physicalTempDir(t)
	_ = os.Chmod(directory, 0o700)
	participant, _ := uuid.NewV7()
	var called atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Store(true)
		if request.URL.Path != "/coordination/v1/sessions" || request.Header.Get("Authorization") != "DPoP external-token" || request.Header.Get("DPoP") == "" {
			t.Error("invalid bootstrap request")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		document, _ := json.Marshal(map[string]any{"expires_at": time.Now().UTC().Add(10 * time.Minute).Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), "participant_instance_id": participant.String(), "session_epoch": 1, "session_token": "jhxeBktt2nliAX1t6s9lggsYVl5SfObUcE0erK6JrjY", "specversion": "0.1", "token_type": "DPoP"})
		document, _ = jsoncanonicalizer.Transform(document)
		writer.Header().Set("Content-Type", "application/yukh-session+json;version=0.1")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write(document)
	}))
	defer server.Close()
	configPath := filepath.Join(directory, "client.json")
	databasePath := filepath.Join(directory, "custody.db")
	config := map[string]any{
		"schema": 1, "profile": "default", "base_uri": server.URL,
		"channel_id": "channel:test", "channel_uri": "https://coord.example/channels/test",
		"transcript_epoch": 1, "page_limit": 100, "max_records": 1000,
		"source_uri": "https://client.example/session", "participant": map[string]any{"id": "agent:test", "kind": "agent"},
		"custody_database": databasePath,
		"receipt_keys":     []map[string]any{{"key_id": "key-1", "public_key": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}},
	}
	raw, _ := json.Marshal(config)
	_ = os.WriteFile(configPath, raw, 0o600)
	rootKey := [32]byte{1, 2, 3, 4}
	rootRead, rootWrite, _ := os.Pipe()
	_, _ = rootWrite.Write(rootKey[:])
	_ = rootWrite.Close()
	rootDescriptor, _ := unix.Dup(int(rootRead.Fd()))
	sockets, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	supervisor := os.NewFile(uintptr(sockets[1]), "token-supervisor")
	done := make(chan error, 1)
	go func() {
		defer supervisor.Close()
		request, err := bufio.NewReader(supervisor).ReadBytes('\n')
		if err != nil {
			done <- err
			return
		}
		var publicRequest struct {
			DPoPThumbprint string `json:"dpop_thumbprint"`
		}
		if json.Unmarshal(request, &publicRequest) != nil {
			done <- context.Canceled
			return
		}
		response, _ := json.Marshal(map[string]any{"credential": "external-token", "dpop_thumbprint": publicRequest.DPoPThumbprint, "expires_at": time.Now().UTC().Add(5 * time.Minute).Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), "schema": 1})
		response, _ = jsoncanonicalizer.Transform(response)
		_, err = supervisor.Write(response)
		done <- err
	}()
	args := []string{"--config", configPath, "--root-key-fd", strconv.Itoa(rootDescriptor), "--external-token-fd", strconv.Itoa(sockets[0]), "session", "bootstrap"}
	var stdout bytes.Buffer
	status := (Executable{httpClient: server.Client()}).Run(context.Background(), args, bytes.NewReader(nil), &stdout)
	runtime.KeepAlive(rootRead)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("token supervisor did not receive the bootstrap request: status=%d output=%s", status, stdout.Bytes())
	}
	if status != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("status=%d called=%v output=%s", status, called.Load(), stdout.Bytes())
	}
	verifyRead, verifyWrite, _ := os.Pipe()
	_, _ = verifyWrite.Write(rootKey[:])
	_ = verifyWrite.Close()
	verifyDescriptor, _ := unix.Dup(int(verifyRead.Fd()))
	root, err := localcustody.NewDescriptorRootKeySource(verifyDescriptor, "default")
	if err != nil {
		t.Fatal(err)
	}
	store, err := localcustody.Open(databasePath, root)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Load(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	record, err := stored.Record()
	if err != nil || record.ParticipantInstanceID() != participant.String() {
		t.Fatalf("record participant=%q err=%v", record.ParticipantInstanceID(), err)
	}
	_ = store.Close()
	_ = root.Close()
	runtime.KeepAlive(verifyRead)
}

func physicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
