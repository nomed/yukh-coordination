package workstation

import (
	"context"
	"io"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"golang.org/x/sys/unix"
)

// RootKeyHandle owns the adapter's use of the duplicated caller-provided D-Bus
// stream. Implementations must reject prompts, locked collections, ambiguous
// items, mismatched attributes, and plaintext transfer fallback.
type RootKeyHandle interface {
	localcustody.RootKeySource
	io.Closer
}

// RootKeyFactory opens one explicitly configured Secret Service root-key
// adapter. On success the returned handle owns bus; on error the caller retains
// and closes bus. It must use only binding and the supplied stream.
type RootKeyFactory interface {
	OpenRootKey(context.Context, SecretServiceBinding, *os.File) (RootKeyHandle, error)
}

// TokenDescriptorReader reads exactly one caller-provided descriptor and
// validates that the result is bound to jwk. It owns neither the original nor
// the duplicated descriptor and must not use an environment or file fallback.
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

// Dependencies are supplied by an embedding executable. There is deliberately
// no default Secret Service protocol, token parser, or HTTP transport.
type Dependencies struct {
	RootKeys    RootKeyFactory
	TokenReader TokenDescriptorReader
	Transport   http.RoundTripper
	OpenStore   OpenStore
}

// Factory constructs only the accepted linux-secret-service-v1 profile.
type Factory struct{ dependencies Dependencies }

func NewFactory(dependencies Dependencies) (*Factory, error) {
	if nilValue(dependencies.RootKeys) || nilValue(dependencies.TokenReader) || nilValue(dependencies.Transport) {
		return nil, ErrInvalidConfiguration
	}
	if dependencies.OpenStore == nil {
		dependencies.OpenStore = func(path string, root localcustody.RootKeySource) (LocalStore, error) {
			return localcustody.Open(path, root)
		}
	}
	return &Factory{dependencies: dependencies}, nil
}

// Open parses and validates configuration before duplicating either caller
// descriptor. The original descriptors remain caller-owned throughout.
func (f *Factory) Open(ctx context.Context, configPath string, tokenFD, busFD int) (*BootstrapProfile, error) {
	if f == nil || ctx == nil || ctx.Err() != nil || tokenFD < 3 || busFD < 3 || tokenFD == busFD {
		return nil, clientauth.ErrInvalidCredential
	}
	if nilValue(f.dependencies.RootKeys) || nilValue(f.dependencies.TokenReader) || nilValue(f.dependencies.Transport) || f.dependencies.OpenStore == nil {
		return nil, clientauth.ErrCredentialStore
	}
	config, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, clientauth.ErrInvalidCredential
	}
	token, err := duplicateReadDescriptor(tokenFD)
	if err != nil {
		return nil, clientauth.ErrInvalidCredential
	}
	bus, err := duplicateBusDescriptor(busFD)
	if err != nil {
		_ = token.Close()
		return nil, clientauth.ErrInvalidCredential
	}
	closeOwned := func(handle RootKeyHandle, store LocalStore) {
		_ = token.Close()
		if store != nil {
			_ = store.Close()
		}
		if handle != nil {
			_ = handle.Close()
		} else {
			_ = bus.Close()
		}
	}
	connection, cancel := context.WithTimeout(ctx, config.ConnectionDeadline())
	handle, err := f.dependencies.RootKeys.OpenRootKey(connection, config.SecretServiceBinding(), bus)
	cancel()
	if err != nil || nilValue(handle) {
		closeOwned(nil, nil)
		return nil, clientauth.ErrCredentialStore
	}
	store, err := f.dependencies.OpenStore(config.LocalCustodyDatabasePath(), handle)
	if err != nil || nilValue(store) {
		closeOwned(handle, nil)
		return nil, clientauth.ErrCredentialStore
	}
	issuer, err := clientauth.NewHTTPIssuer(config.RelayBaseURI(), &http.Client{Transport: f.dependencies.Transport})
	if err != nil {
		closeOwned(handle, store)
		return nil, clientauth.ErrInvalidCredential
	}
	tokens := &descriptorTokenSource{descriptor: token, reader: f.dependencies.TokenReader}
	bootstrapper, err := clientauth.NewBootstrapper(store, store, tokens, requestDeadlineIssuer{issuer: issuer, deadline: config.RequestDeadline()}, config.Profile())
	if err != nil {
		_ = tokens.Close()
		closeOwned(handle, store)
		return nil, clientauth.ErrCredentialStore
	}
	return &BootstrapProfile{bootstrapper: bootstrapper, tokens: tokens, store: store, root: handle, deadline: config.OperationDeadline()}, nil
}

// BootstrapProfile owns one local store, one root-key adapter and one
// duplicated token descriptor. It is safe to close exactly once.
type BootstrapProfile struct {
	bootstrapper *clientauth.Bootstrapper
	tokens       *descriptorTokenSource
	store        LocalStore
	root         RootKeyHandle
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
		var failed bool
		if p.tokens == nil || p.tokens.Close() != nil {
			failed = true
		}
		if p.store == nil || p.store.Close() != nil {
			failed = true
		}
		if p.root == nil || p.root.Close() != nil {
			failed = true
		}
		if failed {
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
	return duplicateDescriptor(descriptor, "bootstrap-token")
}

func duplicateBusDescriptor(descriptor int) (*os.File, error) {
	var stat unix.Stat_t
	if unix.Fstat(descriptor, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, ErrInvalidConfiguration
	}
	socketType, err := unix.GetsockoptInt(descriptor, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || socketType != unix.SOCK_STREAM {
		return nil, ErrInvalidConfiguration
	}
	if _, err := unix.Getpeername(descriptor); err != nil {
		return nil, ErrInvalidConfiguration
	}
	return duplicateDescriptor(descriptor, "bootstrap-bus")
}

func duplicateDescriptor(descriptor int, name string) (*os.File, error) {
	copy, err := unix.FcntlInt(uintptr(descriptor), unix.F_DUPFD_CLOEXEC, 64)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(copy), name)
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
