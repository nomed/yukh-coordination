package macosprofile

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
	"github.com/nomed/yukh-coordination/internal/clientauth/keychain"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
)

func TestParseConfigRejectsOtherProfilesAndClosedBoundaryViolations(t *testing.T) {
	directory := privateDirectory(t)
	keychainPath := privateKeychainFile(t, directory)
	valid := validConfig(filepath.Join(directory, "custody.db"), keychainPath)
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"linux-profile", strings.Replace(string(valid), Profile, "linux-secret-service-v1", 1)},
		{"unknown-profile", strings.Replace(string(valid), Profile, "gcp-workload-v1", 1)},
		{"missing-profile", strings.Replace(string(valid), `"profile":"macos-keychain-v1",`, "", 1)},
		{"unknown-field", strings.TrimSuffix(string(valid), "}") + `,"fallback_profile":"linux-secret-service-v1"}`},
		{"duplicate-profile", strings.Replace(string(valid), `"profile":"macos-keychain-v1"`, `"profile":"macos-keychain-v1","profile":"linux-secret-service-v1"`, 1)},
		{"cross-wired-account", strings.Replace(string(valid), opaqueProfile, otherOpaqueProfile, 1)},
		{"data-protection-access-group", strings.Replace(string(valid), `"keychain_access_group":""`, `"keychain_access_group":"ABCDE12345.com.example.yukh"`, 1)},
		{"ambient-relay", strings.Replace(string(valid), `"https://relay.example"`, `"https://user@relay.example?token=ambient"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if config, err := ParseConfig([]byte(test.raw)); err == nil || config != nil {
				t.Fatalf("accepted config=%#v err=%v", config, err)
			}
		})
	}
	t.Setenv("YUKH_BOOTSTRAP_PROFILE", "linux-secret-service-v1")
	t.Setenv("YUKH_BOOTSTRAP_TOKEN", "ambient-token")
	config, err := ParseConfig(valid)
	if err != nil || config.Profile() != Profile || config.CustodyProfile() != opaqueProfile ||
		config.KeychainPath() != keychainPath || config.String() != "Config{REDACTED}" ||
		config.GoString() != "Config{REDACTED}" {
		t.Fatalf("ambient state affected config: config=%v err=%v", config, err)
	}
}

func TestLoadConfigFileRequiresPrivateConfigurationAndPaths(t *testing.T) {
	directory := privateDirectory(t)
	path := writeConfig(t, directory)
	if _, err := LoadConfigFile(path); err != nil {
		t.Fatalf("load valid config: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path); err == nil {
		t.Fatal("accepted public config")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(path); err == nil {
		t.Fatal("accepted public config directory")
	}
}

func TestConfigRejectsKeychainDatabaseAliases(t *testing.T) {
	directory := privateDirectory(t)
	keychainPath := privateKeychainFile(t, directory)
	databasePath := filepath.Join(directory, "custody.db")
	if err := os.Link(keychainPath, databasePath); err != nil {
		t.Fatal(err)
	}
	raw := validConfig(databasePath, keychainPath)
	config, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("parse hard-linked paths: %v", err)
	}
	if err := config.ValidatePaths(); err == nil {
		t.Fatal("accepted Keychain and local custody database aliases")
	}
	configPath := filepath.Join(directory, "bootstrap.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if config, err := LoadConfigFile(configPath); err == nil || config != nil {
		t.Fatalf("loaded Keychain and local custody database aliases: config=%#v err=%v", config, err)
	}
	if config, err := ParseConfig(validConfig(keychainPath, keychainPath)); err == nil || config != nil {
		t.Fatalf("accepted identical paths: config=%#v err=%v", config, err)
	}
}

func TestFactoryRejectsLinuxProfileBeforeTokenOrCustody(t *testing.T) {
	directory := privateDirectory(t)
	raw := strings.Replace(string(validConfig(filepath.Join(directory, "custody.db"), privateKeychainFile(t, directory))), Profile, "linux-secret-service-v1", 1)
	path := filepath.Join(directory, "bootstrap.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	roots := &rootSourceFactoryStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    roots.New,
		TokenReader: &tokenReaderStub{},
		Transport:   &transportStub{},
		OpenStore: func(string, localcustody.RootKeySource) (LocalStore, error) {
			t.Fatal("opened store for Linux profile")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Open(context.Background(), path, int(read.Fd())); !errors.Is(err, clientauth.ErrInvalidCredential) {
		t.Fatalf("open error=%v", err)
	}
	if roots.calls != 0 {
		t.Fatalf("root source opened for rejected profile: %d", roots.calls)
	}
	if _, err := read.Stat(); err != nil {
		t.Fatalf("caller token descriptor closed: %v", err)
	}
}

func TestFactoryRejectsAmbientProxyTransport(t *testing.T) {
	factory, err := NewFactory(Dependencies{
		TokenReader: &tokenReaderStub{},
		Transport:   &http.Transport{Proxy: http.ProxyFromEnvironment},
	})
	if err == nil || factory != nil {
		t.Fatalf("accepted ambient proxy transport: factory=%v err=%v", factory, err)
	}
}

func TestFactoryComposesOnlyInjectedMacOSDependencies(t *testing.T) {
	directory := privateDirectory(t)
	path := writeConfig(t, directory)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if _, err := write.Write([]byte("synthetic-descriptor-token")); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}

	roots := &rootSourceFactoryStub{}
	signer := fixedSigner(t)
	store := &storeStub{signer: signer}
	tokens := &tokenReaderStub{expected: signer.jwk.Thumbprint()}
	transport := &transportStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    roots.New,
		TokenReader: tokens,
		Transport:   transport,
		OpenStore: func(database string, source localcustody.RootKeySource) (LocalStore, error) {
			if database != filepath.Join(directory, "custody.db") || source != roots.source {
				t.Fatalf("unexpected store inputs: %q %#v", database, source)
			}
			return store, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := factory.Open(context.Background(), path, int(read.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := profile.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if roots.calls != 1 || roots.source.rootCalls != 1 || roots.binding.Profile() != opaqueProfile || roots.binding.Service() != keychain.RootItemService ||
		roots.binding.KeychainPath() != filepath.Join(directory, "root.keychain-db") ||
		roots.policy != keychain.CreationAllowed || store.closeCalls != 1 || tokens.calls != 1 || transport.calls != 1 {
		t.Fatalf("roots=%d rootCalls=%d binding=%#v policy=%d close=%d token=%d transport=%d", roots.calls, roots.source.rootCalls, roots.binding, roots.policy, store.closeCalls, tokens.calls, transport.calls)
	}
	if _, err := read.Stat(); err != nil {
		t.Fatalf("caller token descriptor closed: %v", err)
	}
}

func TestFactoryUsesInjectedRootWithEncryptedLocalCustody(t *testing.T) {
	directory := privateDirectory(t)
	path := writeConfig(t, directory)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if _, err := write.Write([]byte("synthetic-descriptor-token")); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	roots := &rootSourceFactoryStub{}
	transport := &transportStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    roots.New,
		TokenReader: permissiveTokenReader{},
		Transport:   transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := factory.Open(context.Background(), path, int(read.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Bootstrap(context.Background()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := profile.Close(); err != nil {
		t.Fatal(err)
	}
	if roots.calls != 1 || roots.source.rootCalls < 4 || transport.calls != 1 {
		t.Fatalf("roots=%d rootCalls=%d transport=%d", roots.calls, roots.source.rootCalls, transport.calls)
	}
	for _, databaseFile := range []string{
		filepath.Join(directory, "custody.db"),
		filepath.Join(directory, "custody.db-wal"),
		filepath.Join(directory, "custody.db-shm"),
	} {
		raw, err := os.ReadFile(databaseFile)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")) {
			t.Fatalf("plaintext session token in %s", databaseFile)
		}
	}
}

func TestFactoryProhibitsReplacementRootForExistingDatabase(t *testing.T) {
	directory := privateDirectory(t)
	path := writeConfig(t, directory)
	database := filepath.Join(directory, "custody.db")
	if err := os.WriteFile(database, []byte("existing-local-custody-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	roots := &rootSourceFactoryStub{}
	factory, err := NewFactory(Dependencies{
		RootKeys:    roots.New,
		TokenReader: &tokenReaderStub{},
		Transport:   &transportStub{},
		OpenStore: func(string, localcustody.RootKeySource) (LocalStore, error) {
			return nil, errors.New("do not open synthetic existing database")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Open(context.Background(), path, int(read.Fd())); !errors.Is(err, clientauth.ErrCredentialStore) {
		t.Fatalf("open error=%v", err)
	}
	if roots.calls != 1 || roots.source.rootCalls != 1 || roots.policy != keychain.CreationProhibited {
		t.Fatalf("existing database policy: calls=%d rootCalls=%d policy=%d", roots.calls, roots.source.rootCalls, roots.policy)
	}
}

const (
	opaqueProfile      = "0123456789abcdef0123456789abcdef"
	otherOpaqueProfile = "fedcba9876543210fedcba9876543210"
)

func validConfig(database, keychainPath string) []byte {
	value := map[string]any{
		"profile":                     Profile,
		"custody_profile":             opaqueProfile,
		"local_custody_database_path": database,
		"relay_base_uri":              "https://relay.example",
		"keychain_path":               keychainPath,
		"keychain_service":            keychain.RootItemService,
		"keychain_account":            opaqueProfile,
		"keychain_access_group":       "",
		"request_deadline_ms":         200,
		"operation_deadline_ms":       300,
	}
	raw, _ := json.Marshal(value)
	return raw
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".macosprofile-test-")
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
	if err := os.WriteFile(path, validConfig(filepath.Join(directory, "custody.db"), privateKeychainFile(t, directory)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func privateKeychainFile(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "root.keychain-db")
	if err := os.WriteFile(path, []byte("synthetic-private-keychain"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type rootSourceFactoryStub struct {
	calls   int
	binding keychain.Binding
	policy  keychain.CreationPolicy
	source  *rootSourceStub
}

func (s *rootSourceFactoryStub) New(binding keychain.Binding, policy keychain.CreationPolicy) (localcustody.RootKeySource, error) {
	s.calls++
	s.binding = binding
	s.policy = policy
	s.source = &rootSourceStub{}
	return s.source, nil
}

type rootSourceStub struct{ rootCalls int }

func (s *rootSourceStub) RootKey(context.Context, string) ([32]byte, error) {
	s.rootCalls++
	return [32]byte{1}, nil
}

type tokenReaderStub struct {
	expected [32]byte
	calls    int
}

func (s *tokenReaderStub) ReadBoundAccessToken(_ context.Context, descriptor *os.File, jwk clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	s.calls++
	if descriptor == nil || jwk.Thumbprint() != s.expected {
		return nil, errors.New("unexpected token reader binding")
	}
	raw, err := io.ReadAll(descriptor)
	if err != nil || !bytes.Equal(raw, []byte("synthetic-descriptor-token")) {
		return nil, errors.New("unexpected token descriptor")
	}
	return clientauth.NewBoundAccessToken("header.payload.signature", time.Now().UTC().Truncate(time.Millisecond).Add(time.Minute))
}

type permissiveTokenReader struct{}

func (permissiveTokenReader) ReadBoundAccessToken(_ context.Context, descriptor *os.File, _ clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	raw, err := io.ReadAll(descriptor)
	if err != nil || !bytes.Equal(raw, []byte("synthetic-descriptor-token")) {
		return nil, errors.New("unexpected token descriptor")
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
	if _, err := s.stored.Record(); err != nil {
		return clientauth.StoredSession{}, clientauth.ErrCredentialMissing
	}
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
	jwk, err := clientauth.NewPublicP256JWK(private.PublicKey.X.FillBytes(make([]byte, 32)), private.PublicKey.Y.FillBytes(make([]byte, 32)))
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
