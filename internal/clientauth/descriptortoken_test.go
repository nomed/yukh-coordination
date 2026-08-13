package clientauth

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/sys/unix"
)

func TestDescriptorTokenSource(t *testing.T) {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := NewPublicP256JWK(private.X.FillBytes(make([]byte, 32)), private.Y.FillBytes(make([]byte, 32)))
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := os.NewFile(uintptr(descriptors[1]), "token-supervisor-test")
	expires := time.Now().UTC().Add(5 * time.Minute).Truncate(time.Millisecond)
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		request, err := bufio.NewReader(server).ReadBytes('\n')
		if err != nil {
			done <- err
			return
		}
		var publicRequest struct {
			DPoPThumbprint string `json:"dpop_thumbprint"`
		}
		if json.Unmarshal(request, &publicRequest) != nil {
			done <- errors.New("invalid request")
			return
		}
		response, _ := json.Marshal(map[string]any{"credential": "synthetic-token", "dpop_thumbprint": publicRequest.DPoPThumbprint, "expires_at": expires.Format("2006-01-02T15:04:05.000Z"), "schema": 1})
		response, _ = jsoncanonicalizer.Transform(response)
		_, err = server.Write(response)
		done <- err
	}()
	source, _ := NewDescriptorTokenSource(descriptors[0])
	token, err := source.Acquire(context.Background(), jwk)
	if err != nil || token.Credential() != "synthetic-token" || !token.ExpiresAt().Equal(expires) {
		t.Fatalf("token=%v err=%v", token, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := source.Acquire(context.Background(), jwk); !errors.Is(err, ErrExternalToken) {
		t.Fatalf("reuse error=%v", err)
	}
}

func TestDescriptorTokenSourceRejectsWrongBindingAndPipe(t *testing.T) {
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := NewPublicP256JWK(private.X.FillBytes(make([]byte, 32)), private.Y.FillBytes(make([]byte, 32)))
	descriptors, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	server := os.NewFile(uintptr(descriptors[1]), "wrong-binding-test")
	go func() {
		defer server.Close()
		_, _ = bufio.NewReader(server).ReadBytes('\n')
		wrong := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		response, _ := json.Marshal(map[string]any{"credential": "token", "dpop_thumbprint": wrong, "expires_at": "2026-08-13T21:00:00.000Z", "schema": 1})
		response, _ = jsoncanonicalizer.Transform(response)
		_, _ = server.Write(response)
	}()
	source, _ := NewDescriptorTokenSource(descriptors[0])
	if _, err := source.Acquire(context.Background(), jwk); !errors.Is(err, ErrExternalToken) {
		t.Fatalf("binding error=%v", err)
	}
	read, write, _ := os.Pipe()
	_ = write.Close()
	pipeSource, _ := NewDescriptorTokenSource(int(read.Fd()))
	if _, err := pipeSource.Acquire(context.Background(), jwk); !errors.Is(err, ErrExternalToken) {
		t.Fatalf("pipe error=%v", err)
	}
}
