// Package keychain provides the RFC-0027 macOS Keychain generic-password
// root-key boundary. It has no fallback or keychain discovery behavior.
package keychain

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
)

const (
	RootItemService = "yukh-coordination/macos-keychain-root/v1"
	// Legacy file Keychains protect this item while their exact file is unlocked.
	rootItemAccessibility = "legacy-keychain-file-unlocked"
	rootItemLabel         = "Yukh Coordination Root Key"
)

var errUnavailable = errors.New("keychain root key unavailable")

// CreationPolicy determines whether a source may provision a missing root
// item. A profile with pre-existing local custody state must prohibit it.
type CreationPolicy uint8

const (
	CreationProhibited CreationPolicy = iota
	CreationAllowed
)

// Binding is the exact generic-password item schema for one opaque local
// custody profile. It is intentionally redacted from formatting.
type Binding struct {
	profile      string
	service      string
	account      string
	accessGroup  string
	keychainPath string
}

// NewBinding validates an exact RFC-0027 Keychain item schema and private
// caller-created Keychain file. The account must equal the opaque profile so
// the Keychain item cannot be cross-wired to another encrypted local-custody
// database.
func NewBinding(profile, service, account, accessGroup, keychainPath string) (Binding, error) {
	if !validOpaqueProfile(profile) || service != RootItemService || account != profile ||
		accessGroup != "" || !validPrivateKeychainPath(keychainPath) {
		return Binding{}, errUnavailable
	}
	return Binding{profile: profile, service: service, account: account, accessGroup: accessGroup, keychainPath: keychainPath}, nil
}

func (b Binding) Profile() string      { return b.profile }
func (b Binding) Service() string      { return b.service }
func (b Binding) Account() string      { return b.account }
func (b Binding) AccessGroup() string  { return b.accessGroup }
func (b Binding) KeychainPath() string { return b.keychainPath }

func (Binding) String() string   { return "Binding{REDACTED}" }
func (Binding) GoString() string { return "Binding{REDACTED}" }

// Source obtains one root key from one exact Keychain item. It does not cache
// root material and serializes lookup/create to prevent a second local create.
type Source struct {
	binding  Binding
	creation CreationPolicy
	provider provider
	entropy  io.Reader
	mu       sync.Mutex
}

var _ localcustody.RootKeySource = (*Source)(nil)

// NewSource constructs the native Keychain root-key source. On non-darwin
// builds, RootKey fails closed through the platform stub.
func NewSource(binding Binding, creation CreationPolicy) (*Source, error) {
	if !validBinding(binding) || creation > CreationAllowed {
		return nil, errUnavailable
	}
	return &Source{binding: binding, creation: creation, provider: newNativeProvider(), entropy: rand.Reader}, nil
}

// RootKey returns the one valid 32-byte root key for the configured opaque
// profile. A context deadline is required because Keychain calls can block.
func (s *Source) RootKey(ctx context.Context, profile string) ([32]byte, error) {
	var zero [32]byte
	if s == nil || s.provider == nil || s.entropy == nil || ctx == nil || ctx.Err() != nil ||
		!validBinding(s.binding) || profile != s.binding.profile || !validOpaqueProfile(profile) {
		return zero, errUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, errUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key, state, err := s.lookup(ctx)
	if err != nil {
		return zero, errUnavailable
	}
	switch state {
	case rootFound:
		return key, nil
	case rootAbsent:
		if s.creation != CreationAllowed {
			return zero, errUnavailable
		}
		return s.create(ctx)
	default:
		return zero, errUnavailable
	}
}

func (s *Source) create(ctx context.Context) ([32]byte, error) {
	var zero, candidate [32]byte
	if _, err := io.ReadFull(s.entropy, candidate[:]); err != nil || isZero(candidate[:]) {
		clear(candidate[:])
		return zero, errUnavailable
	}
	defer clear(candidate[:])

	ambiguous, err := s.provider.Create(ctx, s.binding, candidate[:])
	if ambiguous {
		return s.reconcile(ctx)
	}
	if err != nil {
		return zero, errUnavailable
	}
	key, state, lookupErr := s.lookup(ctx)
	if lookupErr != nil || state != rootFound || !equal(key[:], candidate[:]) {
		clear(key[:])
		return zero, errUnavailable
	}
	return key, nil
}

// reconcile is the sole retry permitted after an ambiguous create. It never
// calls Create again and requires one exact valid item.
func (s *Source) reconcile(ctx context.Context) ([32]byte, error) {
	var zero [32]byte
	key, state, err := s.lookup(ctx)
	if err != nil || state != rootFound {
		clear(key[:])
		return zero, errUnavailable
	}
	return key, nil
}

type rootState uint8

const (
	rootInvalid rootState = iota
	rootAbsent
	rootFound
)

func (s *Source) lookup(ctx context.Context) ([32]byte, rootState, error) {
	var zero [32]byte
	items, err := s.provider.Lookup(ctx, s.binding)
	if err != nil {
		return zero, rootInvalid, errUnavailable
	}
	defer clearItems(items)
	switch len(items) {
	case 0:
		return zero, rootAbsent, nil
	case 1:
		if !validItem(items[0], s.binding) {
			return zero, rootInvalid, errUnavailable
		}
		var key [32]byte
		copy(key[:], items[0].secret)
		return key, rootFound, nil
	default:
		return zero, rootInvalid, errUnavailable
	}
}

type provider interface {
	Lookup(context.Context, Binding) ([]item, error)
	Create(context.Context, Binding, []byte) (ambiguous bool, err error)
}

type item struct {
	service       string
	account       string
	accessGroup   string
	accessibility string
	label         string
	secret        []byte
}

func validItem(value item, binding Binding) bool {
	return value.service == binding.service && value.account == binding.account &&
		value.accessGroup == binding.accessGroup && value.accessibility == rootItemAccessibility &&
		value.label == rootItemLabel && len(value.secret) == 32 && !isZero(value.secret)
}

func clearItems(items []item) {
	for index := range items {
		clear(items[index].secret)
	}
}

func validBinding(binding Binding) bool {
	expected, err := NewBinding(binding.profile, binding.service, binding.account, binding.accessGroup, binding.keychainPath)
	return err == nil && expected == binding
}

func validOpaqueProfile(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'f' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validPrivateKeychainPath(path string) bool {
	if !exactAbsolutePath(path) || !securePrivateDirectory(filepath.Dir(path)) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && securePrivateRegular(info)
}

func exactAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func securePrivateRegular(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm()&0o077 == 0 && ownedByEffectiveUser(info)
}

func securePrivateDirectory(path string) bool {
	if !exactAbsolutePath(path) {
		return false
	}
	for current := path; current != string(filepath.Separator); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().Perm()&0o077 == 0 && ownedByEffectiveUser(info)
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func isZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
