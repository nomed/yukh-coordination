// Package secretservice provides the RFC-0018 root-key boundary over an
// explicitly supplied D-Bus stream. It never discovers a bus or a service.
package secretservice

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth/localcustody"
	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
)

const (
	rootSchemaAttribute    = "yukh.coordination.root.schema"
	contentSchemaAttribute = "xdg:schema"
	rootProfileAttribute   = "yukh.coordination.root.profile"
	rootContentType        = "application/octet-stream"
	rootLabel              = "Yukh Coordination Root Key"
	maximumCollectionItems = 256
	sessionCloseDeadline   = time.Second
)

var errUnavailable = errors.New("secret service root key unavailable")

// Factory opens the configured Secret Service adapter only on a supplied
// caller-owned stream. A successful handle takes ownership of that stream.
type Factory struct {
	open    func(context.Context, workstation.SecretServiceBinding, *os.File) (rootService, error)
	entropy io.Reader
}

// NewRootKeyFactory creates the production Secret Service root-key factory.
func NewRootKeyFactory() *Factory {
	return &Factory{open: openDBusService, entropy: rand.Reader}
}

// OpenRootKey implements workstation.RootKeyFactory. The original caller
// descriptor is never retained: workstation.Factory passes an owned duplicate.
func (f *Factory) OpenRootKey(ctx context.Context, binding workstation.SecretServiceBinding, bus *os.File) (workstation.RootKeyHandle, error) {
	if f == nil || f.open == nil || f.entropy == nil || ctx == nil || ctx.Err() != nil || bus == nil || !validBinding(binding) {
		return nil, errUnavailable
	}
	service, err := f.open(ctx, binding, bus)
	if err != nil || service == nil {
		return nil, errUnavailable
	}
	return &handle{service: service, binding: binding, entropy: f.entropy}, nil
}

type handle struct {
	service rootService
	binding workstation.SecretServiceBinding
	entropy io.Reader
	mu      sync.Mutex
	closed  bool
}

var _ workstation.RootKeyFactory = (*Factory)(nil)
var _ workstation.RootKeyHandle = (*handle)(nil)
var _ localcustody.RootKeySource = (*handle)(nil)

// RootKey obtains exactly one 32-byte root key for profile. It does not cache
// root material and serializes lookup/create to prevent a second local create.
func (h *handle) RootKey(ctx context.Context, profile string) ([32]byte, error) {
	var zero [32]byte
	if h == nil || h.service == nil || h.entropy == nil || ctx == nil || ctx.Err() != nil || !validProfile(profile) {
		return zero, errUnavailable
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return zero, errUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return zero, errUnavailable
	}
	attributes := rootAttributes(h.binding, profile)
	session, err := h.service.OpenSession(ctx)
	if err != nil {
		return zero, errUnavailable
	}
	key, state, err := h.lookup(ctx, session, attributes)
	closeErr := closeSession(session)
	if err != nil || closeErr != nil {
		clear(key[:])
		return zero, errUnavailable
	}
	switch state {
	case rootFound:
		return key, nil
	case rootAbsent:
		return h.create(ctx, attributes)
	default:
		return zero, errUnavailable
	}
}

func (h *handle) create(ctx context.Context, attributes map[string]string) ([32]byte, error) {
	var zero, candidate [32]byte
	if _, err := io.ReadFull(h.entropy, candidate[:]); err != nil || isZero(candidate[:]) {
		clear(candidate[:])
		return zero, errUnavailable
	}
	defer clear(candidate[:])

	session, err := h.service.OpenSession(ctx)
	if err != nil {
		return zero, errUnavailable
	}
	path, prompt, ambiguous, err := h.service.CreateItem(ctx, session, rootItem{
		attributes: attributes, contentType: rootContentType, label: rootLabel, value: candidate,
	})
	if err != nil || prompt || !validPath(path) {
		closeErr := closeSession(session)
		if closeErr != nil || !ambiguous {
			return zero, errUnavailable
		}
		return h.reconcile(ctx, attributes)
	}
	key, state, lookupErr := h.lookup(ctx, session, attributes)
	closeErr := closeSession(session)
	if lookupErr != nil || closeErr != nil || state != rootFound || subtle.ConstantTimeCompare(key[:], candidate[:]) != 1 {
		clear(key[:])
		return zero, errUnavailable
	}
	return key, nil
}

// reconcile performs the sole retry permitted after a possibly completed
// CreateItem transport failure. It opens a fresh Secret Service session and
// never calls CreateItem again.
func (h *handle) reconcile(ctx context.Context, attributes map[string]string) ([32]byte, error) {
	var zero [32]byte
	session, err := h.service.OpenSession(ctx)
	if err != nil {
		return zero, errUnavailable
	}
	key, state, lookupErr := h.lookup(ctx, session, attributes)
	closeErr := closeSession(session)
	if lookupErr != nil || closeErr != nil || state != rootFound {
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

func (h *handle) lookup(ctx context.Context, session rootSession, attributes map[string]string) ([32]byte, rootState, error) {
	var zero [32]byte
	locked, paths, err := h.service.CollectionItems(ctx)
	if err != nil || locked || len(paths) > maximumCollectionItems {
		return zero, rootInvalid, errUnavailable
	}
	var found *rootItem
	for _, path := range paths {
		if !validPath(path) {
			return zero, rootInvalid, errUnavailable
		}
		metadata, err := h.service.ItemMetadata(ctx, path)
		if err != nil || metadata.path != path {
			return zero, rootInvalid, errUnavailable
		}
		if metadata.attributes[rootProfileAttribute] != attributes[rootProfileAttribute] {
			continue
		}
		if !equalAttributes(metadata.attributes, attributes) || metadata.locked || metadata.contentType != rootContentType || metadata.label != rootLabel {
			return zero, rootInvalid, errUnavailable
		}
		value, contentType, err := h.service.ItemSecret(ctx, session, path)
		if err != nil || contentType != rootContentType || len(value) != len(zero) {
			clear(value)
			return zero, rootInvalid, errUnavailable
		}
		var key [32]byte
		copy(key[:], value)
		clear(value)
		if isZero(key[:]) {
			clear(key[:])
			return zero, rootInvalid, errUnavailable
		}
		if found != nil {
			clear(key[:])
			clear(found.value[:])
			return zero, rootInvalid, errUnavailable
		}
		metadataAgain, err := h.service.ItemMetadata(ctx, path)
		if err != nil || metadataAgain.path != path || metadataAgain.locked ||
			metadataAgain.contentType != rootContentType || metadataAgain.label != rootLabel ||
			!equalAttributes(metadataAgain.attributes, attributes) {
			clear(key[:])
			return zero, rootInvalid, errUnavailable
		}
		found = &rootItem{path: path, value: key}
	}
	if found == nil {
		return zero, rootAbsent, nil
	}
	return found.value, rootFound, nil
}

func (h *handle) Close() error {
	if h == nil {
		return errUnavailable
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.service == nil || h.service.Close() != nil {
		return errUnavailable
	}
	return nil
}

type rootService interface {
	io.Closer
	OpenSession(context.Context) (rootSession, error)
	CollectionItems(context.Context) (locked bool, paths []string, err error)
	ItemMetadata(context.Context, string) (itemMetadata, error)
	ItemSecret(context.Context, rootSession, string) ([]byte, string, error)
	CreateItem(context.Context, rootSession, rootItem) (path string, prompt bool, ambiguous bool, err error)
}

type rootSession interface {
	Close(context.Context) error
}

type itemMetadata struct {
	path        string
	locked      bool
	attributes  map[string]string
	contentType string
	label       string
}

type rootItem struct {
	path        string
	attributes  map[string]string
	contentType string
	label       string
	value       [32]byte
}

func rootAttributes(binding workstation.SecretServiceBinding, profile string) map[string]string {
	return map[string]string{
		contentSchemaAttribute: rootContentType,
		rootSchemaAttribute:    binding.RootItemSchema(),
		rootProfileAttribute:   profile,
	}
}

func validBinding(binding workstation.SecretServiceBinding) bool {
	if binding.Name() != "org.freedesktop.secrets" ||
		binding.RootItemSchema() != workstation.RootItemSchema ||
		!strings.HasPrefix(binding.Collection(), "/org/freedesktop/secrets/collection/") {
		return false
	}
	identifier := strings.TrimPrefix(binding.Collection(), "/org/freedesktop/secrets/collection/")
	if identifier == "" || strings.Contains(identifier, "/") {
		return false
	}
	for index, character := range identifier {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') ||
			(index == 0 && character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validProfile(profile string) bool {
	if profile == "" || len(profile) > 128 {
		return false
	}
	for _, character := range profile {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func validPath(path string) bool {
	if len(path) < 2 || path[0] != '/' || strings.HasSuffix(path, "/") {
		return false
	}
	for _, section := range strings.Split(path[1:], "/") {
		if section == "" {
			return false
		}
		for _, character := range section {
			if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_') {
				return false
			}
		}
	}
	return true
}

func equalAttributes(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for name, value := range expected {
		if actual[name] != value {
			return false
		}
	}
	return true
}

func closeSession(session rootSession) error {
	if session == nil {
		return errUnavailable
	}
	closeContext, cancel := context.WithTimeout(context.Background(), sessionCloseDeadline)
	defer cancel()
	return session.Close(closeContext)
}

func isZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
