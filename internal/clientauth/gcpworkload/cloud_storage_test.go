package gcpworkload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

type fakeObjectBackend struct {
	loaded      objectResult
	loadErr     error
	saved       objectResult
	saveErr     error
	deletedWith Generation
	deleteErr   error
}

func (f *fakeObjectBackend) load(context.Context, Generation) (objectResult, error) {
	return f.loaded, f.loadErr
}
func (f *fakeObjectBackend) save(_ context.Context, _ Generation, _ []byte, _ CRC32C) (objectResult, error) {
	return f.saved, f.saveErr
}
func (f *fakeObjectBackend) delete(_ context.Context, generation Generation) error {
	f.deletedWith = generation
	return f.deleteErr
}

func TestCloudObjectStoreValidatesCompleteRead(t *testing.T) {
	body := validEnvelopeBytes(t)
	backend := &fakeObjectBackend{loaded: objectResult{body: body, generation: 7, checksum: Checksum(body).ProviderValue(), size: int64(len(body))}}
	store, err := newCloudObjectStore(backend, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := loaded.Generation().ProviderValue(); value != 7 {
		t.Fatalf("generation = %d", value)
	}
	backend.loaded.decompressed = true
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("transformed read error = %v", err)
	}
	backend.loaded.decompressed = false
	backend.loaded.checksum++
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("checksum error = %v", err)
	}
}

func TestCloudObjectStoreMapsPreconditionWithoutProviderDetails(t *testing.T) {
	backend := &fakeObjectBackend{deleteErr: &googleapi.Error{Code: 412, Message: "sensitive provider detail"}}
	store, err := newCloudObjectStore(backend, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := NewGeneration(9)
	if err := store.Delete(context.Background(), generation); !errors.Is(err, ErrConflict) || err.Error() != ErrConflict.Error() {
		t.Fatalf("delete error = %v", err)
	}
}

func TestCloudObjectStoreNoAuthLoopbackRead(t *testing.T) {
	body := validEnvelopeBytes(t)
	checksum := Checksum(body).ProviderValue()
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, checksum)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("loopback request unexpectedly carried authorization")
		}
		if request.Method != http.MethodGet || request.URL.Path != "/yukh-custody/profiles/opaque" || request.Header.Get("Range") != "" {
			http.Error(w, "expected complete object read", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Goog-Stored-Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("X-Goog-Generation", "17")
		w.Header().Set("X-Goog-Hash", "crc32c="+base64.StdEncoding.EncodeToString(checksumBytes))
		_, _ = w.Write(body)
	}))
	defer server.Close()

	client, err := storage.NewClient(context.Background(), option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	store, err := NewCloudObjectStore(client, "yukh-custody", "profiles/opaque", time.Second, 2)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if generation, _ := loaded.Generation().ProviderValue(); generation != 17 {
		t.Fatalf("generation = %d", generation)
	}
}

func TestCloudObjectStoreNoAuthLoopbackConditionalMutations(t *testing.T) {
	body := validEnvelopeBytes(t)
	checksum := Checksum(body).ProviderValue()
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, checksum)
	encodedChecksum := base64.StdEncoding.EncodeToString(checksumBytes)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			t.Error("loopback request unexpectedly carried authorization")
		}
		switch request.Method {
		case http.MethodPost:
			if !strings.Contains(request.URL.Path, "/upload/storage/v1/b/yukh-custody/o") || request.URL.Query().Get("ifGenerationMatch") != "0" || request.URL.Query().Get("uploadType") != "multipart" {
				http.Error(w, "missing absent-create precondition", http.StatusBadRequest)
				return
			}
			requestBody, _ := io.ReadAll(request.Body)
			if !bytes.Contains(requestBody, body) {
				http.Error(w, "missing complete envelope", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"bucket":"yukh-custody","name":"profiles/opaque","generation":"17","size":"%d","crc32c":"%s"}`, len(body), encodedChecksum)
		case http.MethodDelete:
			if request.URL.Path != "/b/yukh-custody/o/profiles/opaque" && request.URL.Path != "/b/yukh-custody/o/profiles%2Fopaque" || request.URL.Query().Get("ifGenerationMatch") != "17" {
				http.Error(w, "missing exact delete precondition", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client, err := storage.NewClient(context.Background(), option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	store, err := NewCloudObjectStore(client, "yukh-custody", "profiles/opaque", time.Second, 2)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := store.Save(context.Background(), AbsentGeneration(), body, Checksum(body))
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := generation.ProviderValue(); value != 17 {
		t.Fatalf("generation = %d", value)
	}
	if err := store.Delete(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
}

func validEnvelopeBytes(t *testing.T) []byte {
	t.Helper()
	encryption, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/session/cryptoKeyVersions/1")
	signing, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/proof/cryptoKeyVersions/2")
	profile := sha256Digest(profileDigestDomain + "server")
	thumbprint := sha256Digest("signer")
	aad, err := NewAssociatedData(profile, "yukh-custody", "profiles/opaque", encryption, signing, thumbprint)
	if err != nil {
		t.Fatal(err)
	}
	canonicalAAD, _ := aad.Canonical()
	envelope, err := NewEnvelope(encryption, []byte("0123456789ab"), standardTagBytes, append([]byte("plaintext"), make([]byte, standardTagBytes)...), canonicalAAD)
	if err != nil {
		t.Fatal(err)
	}
	body, err := envelope.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return body
}
