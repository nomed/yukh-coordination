// Package primitivesstaging implements the RFC-0022 private staging security
// foundation. It contains no listener, executable, provider composition or
// deployment defaults.
package primitivesstaging

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Profile = "yukh-coordination/private-primitives-staging-v1"

var (
	ErrInvalid         = errors.New("private primitives staging: invalid")
	ErrUnauthenticated = errors.New("private primitives staging: unauthenticated")
	ErrReplay          = errors.New("private primitives staging: proof replay")
	ErrUnavailable     = errors.New("private primitives staging: unavailable")
)

type configJSON struct {
	Profile                   string `json:"profile"`
	PublicBaseURI             string `json:"public_base_uri"`
	PublicBind                string `json:"public_bind"`
	OperationsBind            string `json:"operations_bind"`
	TLSCertificatePath        string `json:"tls_certificate_path"`
	TLSPrivateKeyPath         string `json:"tls_private_key_path"`
	TLSTrustBundlePath        string `json:"tls_trust_bundle_path"`
	RegistrationPath          string `json:"registration_path"`
	RegistrationSignaturePath string `json:"registration_signature_path"`
	ReplayDatabasePath        string `json:"replay_database_path"`
	RegistrationKeyID         string `json:"registration_key_id"`
	RegistrationPublicKey     string `json:"registration_public_key"`
	RequestDeadlineMS         int    `json:"request_deadline_ms"`
	MaxConcurrentRequests     int    `json:"max_concurrent_requests"`
	MaxReplayEntries          int    `json:"max_replay_entries"`
	Epoch                     uint64 `json:"epoch"`
	NATSCredentialFD          int    `json:"nats_credential_fd"`
	CapabilityKeyFD           int    `json:"capability_key_fd"`
}

type Config struct{ value configJSON }

func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > 16_384 || !closedJSONObject(raw) {
		return nil, ErrInvalid
	}
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Profile != Profile || !exactHTTPSOrigin(value.PublicBaseURI) || !privateBind(value.PublicBind) || !loopbackBind(value.OperationsBind) || !opaque(value.RegistrationKeyID, 128) || !base64url(value.RegistrationPublicKey, 43) || value.RequestDeadlineMS < 1 || value.RequestDeadlineMS > 5_000 || value.MaxConcurrentRequests < 1 || value.MaxConcurrentRequests > 256 || value.MaxReplayEntries < 1 || value.MaxReplayEntries > 100_000 || value.Epoch == 0 || value.Epoch > 9_007_199_254_740_991 || value.NATSCredentialFD < 3 || value.CapabilityKeyFD < 3 || value.NATSCredentialFD == value.CapabilityKeyFD {
		return nil, ErrInvalid
	}
	paths := []string{value.TLSCertificatePath, value.TLSPrivateKeyPath, value.TLSTrustBundlePath, value.RegistrationPath, value.RegistrationSignaturePath, value.ReplayDatabasePath}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, ErrInvalid
		}
		if _, exists := seen[path]; exists {
			return nil, ErrInvalid
		}
		seen[path] = struct{}{}
	}
	return &Config{value: value}, nil
}

func (c *Config) ValidatePaths() error {
	if c == nil {
		return ErrInvalid
	}
	regular := []string{c.value.TLSCertificatePath, c.value.TLSPrivateKeyPath, c.value.TLSTrustBundlePath, c.value.RegistrationPath, c.value.RegistrationSignaturePath}
	for _, path := range regular {
		if !secureRegular(path) {
			return ErrInvalid
		}
	}
	if !secureParent(c.value.ReplayDatabasePath) {
		return ErrInvalid
	}
	if info, err := os.Lstat(c.value.ReplayDatabasePath); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0) {
		return ErrInvalid
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrInvalid
	}
	return nil
}

func (c *Config) PublicBaseURI() string         { return c.value.PublicBaseURI }
func (c *Config) PublicBind() string            { return c.value.PublicBind }
func (c *Config) OperationsBind() string        { return c.value.OperationsBind }
func (c *Config) ReplayDatabasePath() string    { return c.value.ReplayDatabasePath }
func (c *Config) RegistrationKeyID() string     { return c.value.RegistrationKeyID }
func (c *Config) RegistrationPublicKey() string { return c.value.RegistrationPublicKey }
func (c *Config) RequestDeadline() time.Duration {
	return time.Duration(c.value.RequestDeadlineMS) * time.Millisecond
}
func (c *Config) MaxConcurrentRequests() int { return c.value.MaxConcurrentRequests }
func (c *Config) MaxReplayEntries() int      { return c.value.MaxReplayEntries }
func (c *Config) Epoch() uint64              { return c.value.Epoch }
func (*Config) String() string               { return "Config{REDACTED}" }
func (*Config) GoString() string             { return "Config{REDACTED}" }
func (*Config) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func exactHTTPSOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func privateBind(value string) bool {
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	parsedPort, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && parsedPort > 0 && parsedPort <= 65535 && ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func loopbackBind(value string) bool {
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	parsedPort, portErr := strconv.Atoi(port)
	return err == nil && portErr == nil && parsedPort > 0 && parsedPort <= 65535 && ip != nil && ip.IsLoopback()
}

func opaque(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("._:-", char)) {
			return false
		}
	}
	return true
}

func base64url(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func secureRegular(path string) bool {
	if !secureParent(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0
}

func secureParent(path string) bool {
	current := filepath.Clean(path)
	for current != string(filepath.Separator) {
		current = filepath.Dir(current)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	return true
}
