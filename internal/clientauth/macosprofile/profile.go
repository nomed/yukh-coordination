package macosprofile

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
	"github.com/nomed/yukh-coordination/internal/clientauth/keychain"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"golang.org/x/sys/unix"
)

// TokenDescriptorReader reads one caller-owned token descriptor and validates
// its DPoP binding. It must not discover a token from another source.
type TokenDescriptorReader interface {
	ReadBoundAccessToken(context.Context, *os.File, clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error)
}

// LocalStore is the owned encrypted SQLite custody boundary.
type LocalStore interface {
	clientauth.CredentialStore
	clientauth.ProofSignerStore
	io.Closer
}

type OpenStore func(string, localcustody.RootKeySource) (LocalStore, error)

// NewRootKeySource is the injectible native RFC-0028 Keychain root-key constructor.
// The policy is selected only from the configured local custody path state.
type NewRootKeySource func(keychain.Binding, keychain.CreationPolicy) (localcustody.RootKeySource, error)

// Dependencies are supplied by an embedding executable. The transport must be
// an explicitly caller-owned direct HTTPS transport; this package creates no
// default transport, proxy, provider, or ambient identity source.
type Dependencies struct {
	RootKeys    NewRootKeySource
	TokenReader TokenDescriptorReader
	Transport   http.RoundTripper
	OpenStore   OpenStore
}

// Factory constructs only the accepted macos-keychain-v1 profile.
type Factory struct{ dependencies Dependencies }

func NewFactory(dependencies Dependencies) (*Factory, error) {
	if dependencies.RootKeys == nil {
		dependencies.RootKeys = func(binding keychain.Binding, creation keychain.CreationPolicy) (localcustody.RootKeySource, error) {
			return keychain.NewSource(binding, creation)
		}
	}
	if nilValue(dependencies.TokenReader) || nilValue(dependencies.Transport) || !directTransport(dependencies.Transport) {
		return nil, ErrInvalidConfiguration
	}
	if dependencies.OpenStore == nil {
		dependencies.OpenStore = func(path string, root localcustody.RootKeySource) (LocalStore, error) {
			return localcustody.Open(path, root)
		}
	}
	return &Factory{dependencies: dependencies}, nil
}

func directTransport(transport http.RoundTripper) bool {
	if native, ok := transport.(*http.Transport); ok {
		return native != nil && native.Proxy == nil
	}
	return true
}

// Open validates closed configuration and database state before duplicating
// the caller-owned token descriptor. It never contacts a relay.
func (f *Factory) Open(ctx context.Context, configPath string, tokenFD int) (*BootstrapProfile, error) {
	if f == nil || ctx == nil || ctx.Err() != nil || tokenFD < 3 || f.dependencies.RootKeys == nil ||
		nilValue(f.dependencies.TokenReader) || nilValue(f.dependencies.Transport) || f.dependencies.OpenStore == nil {
		return nil, clientauth.ErrInvalidCredential
	}
	config, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, clientauth.ErrInvalidCredential
	}
	creation, err := rootCreationPolicy(config.LocalCustodyDatabasePath())
	if err != nil {
		return nil, clientauth.ErrCredentialStore
	}
	binding, err := config.KeychainBinding()
	if err != nil {
		return nil, clientauth.ErrInvalidCredential
	}
	root, err := f.dependencies.RootKeys(binding, creation)
	if err != nil || nilValue(root) {
		return nil, clientauth.ErrCredentialStore
	}
	rootContext, cancel := context.WithTimeout(ctx, config.OperationDeadline())
	rootKey, rootErr := root.RootKey(rootContext, config.CustodyProfile())
	cancel()
	clear(rootKey[:])
	if rootErr != nil {
		return nil, clientauth.ErrCredentialStore
	}
	token, err := duplicateReadDescriptor(tokenFD)
	if err != nil {
		return nil, clientauth.ErrInvalidCredential
	}
	store, err := f.dependencies.OpenStore(config.LocalCustodyDatabasePath(), root)
	if err != nil || nilValue(store) {
		_ = token.Close()
		return nil, clientauth.ErrCredentialStore
	}
	issuer, err := clientauth.NewHTTPIssuer(config.RelayBaseURI(), &http.Client{Transport: f.dependencies.Transport})
	if err != nil {
		_ = token.Close()
		_ = store.Close()
		return nil, clientauth.ErrInvalidCredential
	}
	tokens := &descriptorTokenSource{descriptor: token, reader: f.dependencies.TokenReader}
	bootstrapper, err := clientauth.NewBootstrapper(store, store, tokens, requestDeadlineIssuer{issuer: issuer, deadline: config.RequestDeadline()}, config.CustodyProfile())
	if err != nil {
		_ = tokens.Close()
		_ = store.Close()
		return nil, clientauth.ErrCredentialStore
	}
	return &BootstrapProfile{bootstrapper: bootstrapper, tokens: tokens, store: store, deadline: config.OperationDeadline()}, nil
}

func rootCreationPolicy(path string) (keychain.CreationPolicy, error) {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		descriptor, createErr := unix.Open(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if createErr != nil {
			return keychain.CreationProhibited, ErrInvalidConfiguration
		}
		if closeErr := unix.Close(descriptor); closeErr != nil {
			return keychain.CreationProhibited, ErrInvalidConfiguration
		}
		info, err = os.Lstat(path)
		if err != nil || !securePrivateRegular(info) {
			return keychain.CreationProhibited, ErrInvalidConfiguration
		}
		// Creation is allowed only after this process atomically reserved a
		// fresh database path. Existing state never authorizes replacement.
		return keychain.CreationAllowed, nil
	case err != nil || !securePrivateRegular(info):
		return keychain.CreationProhibited, ErrInvalidConfiguration
	default:
		// An existing database may contain encrypted state. Denying root-item
		// creation is conservative and prevents replacement after a lost key.
		return keychain.CreationProhibited, nil
	}
}

// BootstrapProfile owns one local store and one duplicated token descriptor.
// The native Keychain source retains neither root material nor an open handle.
type BootstrapProfile struct {
	bootstrapper *clientauth.Bootstrapper
	tokens       *descriptorTokenSource
	store        LocalStore
	deadline     time.Duration
	closed       sync.Once
	closeErr     error
}

func (p *BootstrapProfile) Bootstrap(ctx context.Context) error {
	if p == nil || p.bootstrapper == nil || ctx == nil || p.deadline <= 0 {
		return clientauth.ErrInvalidCredential
	}
	operation, cancel := context.WithTimeout(ctx, p.deadline)
	defer cancel()
	err := p.bootstrapper.Bootstrap(operation)
	if err == nil && operation.Err() != nil {
		return operation.Err()
	}
	return err
}

func (p *BootstrapProfile) Close() error {
	if p == nil {
		return clientauth.ErrCredentialStore
	}
	p.closed.Do(func() {
		if p.tokens == nil || p.tokens.Close() != nil || p.store == nil || p.store.Close() != nil {
			p.closeErr = clientauth.ErrCredentialStore
		}
	})
	return p.closeErr
}

type descriptorTokenSource struct {
	descriptor *os.File
	reader     TokenDescriptorReader
	mu         sync.Mutex
}

func (s *descriptorTokenSource) Acquire(ctx context.Context, jwk clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	if s == nil || ctx == nil || s.reader == nil {
		return nil, clientauth.ErrExternalToken
	}
	s.mu.Lock()
	descriptor := s.descriptor
	s.descriptor = nil
	s.mu.Unlock()
	if descriptor == nil {
		return nil, clientauth.ErrExternalToken
	}
	defer descriptor.Close()
	token, err := s.reader.ReadBoundAccessToken(ctx, descriptor, jwk)
	if err != nil || token == nil || ctx.Err() != nil {
		return nil, clientauth.ErrExternalToken
	}
	return token, nil
}

func (s *descriptorTokenSource) Close() error {
	if s == nil {
		return clientauth.ErrExternalToken
	}
	s.mu.Lock()
	descriptor := s.descriptor
	s.descriptor = nil
	s.mu.Unlock()
	if descriptor != nil {
		return descriptor.Close()
	}
	return nil
}

type requestDeadlineIssuer struct {
	issuer   clientauth.SessionIssuer
	deadline time.Duration
}

func (i requestDeadlineIssuer) Issue(ctx context.Context, token *clientauth.BoundAccessToken, signer clientauth.ProofSigner) (*clientauth.IssuedSession, error) {
	if i.issuer == nil || ctx == nil || i.deadline <= 0 {
		return nil, clientauth.ErrExternalToken
	}
	request, cancel := context.WithTimeout(ctx, i.deadline)
	defer cancel()
	issued, err := i.issuer.Issue(request, token, signer)
	if err != nil || request.Err() != nil {
		return nil, clientauth.ErrExternalToken
	}
	return issued, nil
}

func duplicateReadDescriptor(descriptor int) (*os.File, error) {
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return nil, ErrInvalidConfiguration
	}
	copy, err := unix.FcntlInt(uintptr(descriptor), unix.F_DUPFD_CLOEXEC, 64)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(copy), "macos-bootstrap-token")
	if file == nil {
		_ = unix.Close(copy)
		return nil, ErrInvalidConfiguration
	}
	return file, nil
}

func nilValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
