package localcustody

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

const rootKeyBytes = 32

// DescriptorRootKeySource binds one inherited descriptor to one explicit
// custody profile. The descriptor is consumed and closed at construction; the
// key is never read from an argument, environment variable, or repository file.
type DescriptorRootKeySource struct {
	mu      sync.RWMutex
	profile string
	key     [rootKeyBytes]byte
	closed  bool
}

func NewDescriptorRootKeySource(descriptor int, profile string) (*DescriptorRootKeySource, error) {
	if descriptor < 3 || !validRootProfile(profile) {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(descriptor), "local-custody-root-key")
	if file == nil {
		return nil, ErrRootKeyUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, rootKeyBytes+1))
	if err != nil || len(raw) != rootKeyBytes {
		clear(raw)
		return nil, ErrRootKeyUnavailable
	}
	source := &DescriptorRootKeySource{profile: profile}
	copy(source.key[:], raw)
	clear(raw)
	return source, nil
}

func (s *DescriptorRootKeySource) RootKey(_ context.Context, profile string) ([rootKeyBytes]byte, error) {
	if s == nil {
		return [rootKeyBytes]byte{}, ErrRootKeyUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || subtle.ConstantTimeCompare([]byte(profile), []byte(s.profile)) != 1 {
		return [rootKeyBytes]byte{}, ErrRootKeyUnavailable
	}
	return s.key, nil
}

func (s *DescriptorRootKeySource) Close() error {
	if s == nil {
		return ErrRootKeyUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("local custody: root key source closed")
	}
	clear(s.key[:])
	s.profile = ""
	s.closed = true
	return nil
}

func validRootProfile(profile string) bool {
	return profile != "" && len(profile) <= 128 && !strings.ContainsAny(profile, "/\\\x00") && profile != "." && profile != ".."
}
