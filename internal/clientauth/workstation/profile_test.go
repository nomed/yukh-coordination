package workstation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"golang.org/x/sys/unix"
)

func TestParseConfigRejectsClosedBoundaryViolations(t *testing.T) {
	valid := validConfig("/private/custody.db")
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"unknown", `{"profile":"linux-secret-service-v1","local_custody_database_path":"/private/custody.db","relay_base_uri":"https://relay.example","secret_service_name":"org.freedesktop.secrets","secret_service_collection_path":"/org/freedesktop/secrets/collection/yukh","secret_service_root_item_schema":"yukh-coordination/linux-secret-service-root/v1","connection_deadline_ms":100,"request_deadline_ms":200,"operation_deadline_ms":300,"unknown":true}`},
		{"duplicate", strings.Replace(string(valid), `"profile":"linux-secret-service-v1"`, `"profile":"linux-secret-service-v1","profile":"other"`, 1)},
		{"ambient-relay", strings.Replace(string(valid), `"https://relay.example"`, `"https://user@relay.example?token=ambient"`, 1)},
		{"alias-collection", strings.Replace(string(valid), `/collection/yukh`, `/aliases/default`, 1)},
		{"wrong-profile", strings.Replace(string(valid), Profile, "another-profile", 1)},
		{"unbounded-deadline", strings.Replace(string(valid), `"operation_deadline_ms":300`, `"operation_deadline_ms":30001`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if config, err := ParseConfig([]byte(test.raw)); err == nil || config != nil {
				t.Fatalf("accepted invalid configuration: %#v", config)
			}
		})
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/ambient")
	t.Setenv("YUKH_BOOTSTRAP_TOKEN", "ambient-token")
	if config, err := ParseConfig(valid); err != nil || config.RelayBaseURI() != "https://relay.example" {
		t.Fatalf("ambient values affected parse: config=%v err=%v", config, err)
	}
}

func TestLoadConfigFileRequiresPrivateRegularFileAndDirectory(t *testing.T) {
	directory := privateDirectory(t)
	configPath := filepath.Join(directory, "bootstrap.json")
	if err := os.WriteFile(configPath, validConfig(filepath.Join(directory, "custody.db")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(configPath); err != nil {
		t.Fatalf("load valid configuration: %v", err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(configPath); err == nil {
		t.Fatal("accepted world-readable configuration")
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(configPath); err == nil {
		t.Fatal("accepted non-private configuration directory")
	}
}

func TestFactoryRejectsDescriptorViolationsBeforeRootKeyAccess(t *testing.T) {
	directory := privateDirectory(t)
	configPath := writeConfig(t, directory)
	root := &rootFactoryStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    root,
		TokenReader: &tokenReaderStub{},
		Transport:   &transportStub{},
		OpenStore: func(string, localcustody.RootKeySource) (LocalStore, error) {
			t.Fatal("store opened")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err := factory.Open(context.Background(), configPath, int(write.Fd()), int(read.Fd())); !errors.Is(err, clientauth.ErrInvalidCredential) {
		t.Fatalf("invalid descriptor error = %v", err)
	}
	if root.calls != 0 {
		t.Fatalf("root key access after invalid descriptors: %d", root.calls)
	}
}

func TestFactoryComposesExplicitDependenciesAndClosesOnlyOwnedDescriptors(t *testing.T) {
	directory := privateDirectory(t)
	configPath := writeConfig(t, directory)
	tokenRead, tokenWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer tokenRead.Close()
	if _, err := tokenWrite.Write([]byte("synthetic-descriptor-token")); err != nil {
		t.Fatal(err)
	}
	if err := tokenWrite.Close(); err != nil {
		t.Fatal(err)
	}
	busPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	bus := os.NewFile(uintptr(busPair[0]), "caller-bus")
	defer bus.Close()
	defer unix.Close(busPair[1])

	signer := fixedSigner(t)
	store := &storeStub{signer: signer}
	root := &rootFactoryStub{}
	tokens := tokenReaderStub{expected: signer.jwk.Thumbprint()}
	transport := &transportStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    root,
		TokenReader: &tokens,
		Transport:   transport,
		OpenStore: func(path string, source localcustody.RootKeySource) (LocalStore, error) {
			if path != filepath.Join(directory, "custody.db") || source == nil {
				t.Fatalf("unexpected store dependency: %q %#v", path, source)
			}
			return store, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := factory.Open(context.Background(), configPath, int(tokenRead.Fd()), int(bus.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := profile.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if root.calls != 1 || root.binding.Name() != "org.freedesktop.secrets" ||
		root.binding.Collection() != "/org/freedesktop/secrets/collection/yukh" ||
		root.binding.RootItemSchema() != RootItemSchema || root.handle.closeCalls != 1 ||
		store.closeCalls != 1 || tokens.calls != 1 || transport.calls != 1 {
		t.Fatalf("root=%d binding=%#v rootClose=%d storeClose=%d tokens=%d transport=%d", root.calls, root.binding, root.handle.closeCalls, store.closeCalls, tokens.calls, transport.calls)
	}
	if _, err := unix.FcntlInt(tokenRead.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatalf("token caller descriptor was closed: %v", err)
	}
	if _, err := unix.FcntlInt(bus.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatalf("bus caller descriptor was closed: %v", err)
	}
}

func validConfig(databasePath string) []byte {
	value := map[string]any{
		"profile":                         Profile,
		"local_custody_database_path":     databasePath,
		"relay_base_uri":                  "https://relay.example",
		"secret_service_name":             "org.freedesktop.secrets",
		"secret_service_collection_path":  "/org/freedesktop/secrets/collection/yukh",
		"secret_service_root_item_schema": RootItemSchema,
		"connection_deadline_ms":          100,
		"request_deadline_ms":             200,
		"operation_deadline_ms":           300,
	}
	raw, _ := json.Marshal(value)
	return raw
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".workstation-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func writeConfig(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "bootstrap.json")
	if err := os.WriteFile(path, validConfig(filepath.Join(directory, "custody.db")), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type rootFactoryStub struct {
	calls   int
	binding SecretServiceBinding
	handle  *rootHandleStub
}

func (s *rootFactoryStub) OpenRootKey(_ context.Context, binding SecretServiceBinding, bus *os.File) (RootKeyHandle, error) {
	s.calls++
	if bus == nil || bus.Fd() < 64 {
		return nil, errors.New("caller bus was not duplicated")
	}
	s.binding = binding
	s.handle = &rootHandleStub{bus: bus}
	return s.handle, nil
}

type rootHandleStub struct {
	bus        *os.File
	closeCalls int
}

func (*rootHandleStub) RootKey(context.Context, string) ([32]byte, error) {
	return [32]byte{1}, nil
}

func (s *rootHandleStub) Close() error {
	s.closeCalls++
	return s.bus.Close()
}

type tokenReaderStub struct {
	expected [32]byte
	calls    int
}

func (s *tokenReaderStub) ReadBoundAccessToken(_ context.Context, descriptor *os.File, jwk clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	s.calls++
	if descriptor == nil || jwk.Thumbprint() != s.expected {
		return nil, errors.New("token reader received unexpected descriptor binding")
	}
	raw, err := io.ReadAll(descriptor)
	if err != nil || !bytes.Equal(raw, []byte("synthetic-descriptor-token")) {
		return nil, errors.New("token descriptor was not read exactly")
	}
	return clientauth.NewBoundAccessToken("header.payload.signature", time.Now().UTC().Truncate(time.Millisecond).Add(time.Minute))
}

type transportStub struct{ calls int }

func (s *transportStub) RoundTrip(request *http.Request) (*http.Response, error) {
	s.calls++
	if request.Method != http.MethodPost || request.URL.String() != "https://relay.example/coordination/v1/sessions" ||
		request.Header.Get("Authorization") != "DPoP header.payload.signature" || request.Header.Get("DPoP") == "" {
		return nil, errors.New("unexpected bootstrap request")
	}
	expires := time.Now().UTC().Truncate(time.Millisecond).Add(time.Minute).Format("2006-01-02T15:04:05.000Z")
	body := `{"expires_at":"` + expires + `","participant_instance_id":"019c6f5b-7c00-7000-8000-000000000401","session_epoch":1,"session_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","specversion":"0.1","token_type":"DPoP"}`
	return &http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type":  []string{"application/yukh-session+json;version=0.1"},
			"Cache-Control": []string{"no-store"},
			"Pragma":        []string{"no-cache"},
		},
		Body:    io.NopCloser(strings.NewReader(body)),
		Request: request,
	}, nil
}

type storeStub struct {
	signer     *signerStub
	stored     clientauth.StoredSession
	closeCalls int
}

func (s *storeStub) Load(context.Context, string) (clientauth.StoredSession, error) {
	return s.stored, nil
}

func (s *storeStub) Save(_ context.Context, _ string, expected clientauth.Revision, record *clientauth.SessionRecord) (clientauth.Revision, error) {
	if !expected.IsAbsent() {
		return clientauth.Revision{}, clientauth.ErrCredentialConflict
	}
	revision, _ := clientauth.NewRevision("synthetic-revision")
	stored, err := clientauth.NewStoredSession(record, revision)
	if err != nil {
		return clientauth.Revision{}, err
	}
	s.stored = stored
	return revision, nil
}

func (*storeStub) Delete(context.Context, string, clientauth.Revision) error {
	return clientauth.ErrCredentialConflict
}

func (s *storeStub) ProvisionP256(context.Context, string) (clientauth.ProvisionedSigner, error) {
	return clientauth.NewProvisionedSigner(s.signer, false)
}

func (s *storeStub) Open(context.Context, string) (clientauth.ProofSigner, error) {
	return s.signer, nil
}

func (*storeStub) Retire(context.Context, string) error { return clientauth.ErrProofSigner }

func (s *storeStub) Close() error {
	s.closeCalls++
	return nil
}

type signerStub struct {
	private *ecdsa.PrivateKey
	jwk     clientauth.PublicP256JWK
}

func fixedSigner(t *testing.T) *signerStub {
	t.Helper()
	private := &ecdsa.PrivateKey{D: big.NewInt(1)}
	private.PublicKey.Curve = elliptic.P256()
	private.PublicKey.X, private.PublicKey.Y = private.PublicKey.Curve.ScalarBaseMult(private.D.Bytes())
	x, y := private.PublicKey.X.FillBytes(make([]byte, 32)), private.PublicKey.Y.FillBytes(make([]byte, 32))
	jwk, err := clientauth.NewPublicP256JWK(x, y)
	if err != nil {
		t.Fatal(err)
	}
	return &signerStub{private: private, jwk: jwk}
}

func (*signerStub) KeyReference() string { return "local-p256:synthetic" }
func (s *signerStub) PublicJWK() (clientauth.PublicP256JWK, error) {
	return s.jwk, nil
}

func (s *signerStub) SignES256(_ context.Context, input []byte) ([64]byte, error) {
	digest := sha256.Sum256(input)
	r, value, err := ecdsa.Sign(repeatingReader{}, s.private, digest[:])
	if err != nil {
		return [64]byte{}, err
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	value.FillBytes(signature[32:])
	return signature, nil
}

type repeatingReader struct{}

func (repeatingReader) Read(value []byte) (int, error) {
	for index := range value {
		value[index] = byte(index%251 + 1)
	}
	return len(value), nil
}
