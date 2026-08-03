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
	"sync/atomic"
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
	AuditDatabasePath         string `json:"audit_database_path"`
	RegistrationKeyID         string `json:"registration_key_id"`
	RegistrationPublicKey     string `json:"registration_public_key"`
	RequestDeadlineMS         int    `json:"request_deadline_ms"`
	MaxConcurrentRequests     int    `json:"max_concurrent_requests"`
	MaxReplayEntries          int    `json:"max_replay_entries"`
	MaxLeaseLifetimeMS        int    `json:"max_lease_lifetime_ms"`
	NATSServerURI             string `json:"nats_server_uri"`
	NATSConnectTimeoutMS      int    `json:"nats_connect_timeout_ms"`
	NATSRequestTimeoutMS      int    `json:"nats_request_timeout_ms"`
	NATSReplicas              int    `json:"nats_replicas"`
	NATSReplaySafetyWindowMS  int    `json:"nats_replay_safety_window_ms"`
	NATSRetentionMS           int    `json:"nats_retention_ms"`
	CapabilityLimit           int    `json:"capability_limit"`
	CapabilityPendingTTLMS    int    `json:"capability_pending_ttl_ms"`
	Epoch                     uint64 `json:"epoch"`
}

type Config struct{ value configJSON }

// SecretDescriptors is constructed by the supervisor and is deliberately not
// part of the serializable configuration surface.
type SecretDescriptors struct {
	natsCredential  int
	capabilityKey   int
	natsTaken       atomic.Bool
	capabilityTaken atomic.Bool
}

func NewSecretDescriptors(natsCredential, capabilityKey int) (*SecretDescriptors, error) {
	if natsCredential < 3 || capabilityKey < 3 || natsCredential == capabilityKey {
		return nil, ErrInvalid
	}
	return &SecretDescriptors{natsCredential: natsCredential, capabilityKey: capabilityKey}, nil
}

func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > 16_384 || !closedJSONObject(raw) {
		return nil, ErrInvalid
	}
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Profile != Profile || !exactHTTPSOrigin(value.PublicBaseURI) || !privateBind(value.PublicBind) || !loopbackBind(value.OperationsBind) || !exactNATSServer(value.NATSServerURI) || !opaque(value.RegistrationKeyID, 128) || !base64url(value.RegistrationPublicKey, 43) || value.RequestDeadlineMS < 1 || value.RequestDeadlineMS > 5_000 || value.MaxConcurrentRequests < 1 || value.MaxConcurrentRequests > 256 || value.MaxReplayEntries < 1 || value.MaxReplayEntries > 100_000 || value.MaxLeaseLifetimeMS < 1 || value.MaxLeaseLifetimeMS > 900_000 || value.NATSConnectTimeoutMS < 1 || value.NATSConnectTimeoutMS > 5_000 || value.NATSRequestTimeoutMS < 1 || value.NATSRequestTimeoutMS > 5_000 || value.NATSReplicas < 1 || value.NATSReplicas > 5 || value.NATSReplaySafetyWindowMS < value.MaxLeaseLifetimeMS || value.NATSReplaySafetyWindowMS > 86_400_000 || value.NATSRetentionMS <= value.MaxLeaseLifetimeMS+value.NATSReplaySafetyWindowMS || value.NATSRetentionMS > 604_800_000 || value.CapabilityLimit < 1 || value.CapabilityLimit > 32 || value.CapabilityPendingTTLMS < 1 || value.CapabilityPendingTTLMS > value.NATSRequestTimeoutMS || value.Epoch == 0 || value.Epoch > 9_007_199_254_740_991 {
		return nil, ErrInvalid
	}
	paths := []string{value.TLSCertificatePath, value.TLSPrivateKeyPath, value.TLSTrustBundlePath, value.RegistrationPath, value.RegistrationSignaturePath, value.ReplayDatabasePath, value.AuditDatabasePath}
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
	for _, path := range []string{c.value.ReplayDatabasePath, c.value.AuditDatabasePath} {
		if !secureParent(path) {
			return ErrInvalid
		}
		if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0) {
			return ErrInvalid
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrInvalid
		}
	}
	return nil
}

func (c *Config) PublicBaseURI() string         { return c.value.PublicBaseURI }
func (c *Config) PublicBind() string            { return c.value.PublicBind }
func (c *Config) OperationsBind() string        { return c.value.OperationsBind }
func (c *Config) ReplayDatabasePath() string    { return c.value.ReplayDatabasePath }
func (c *Config) AuditDatabasePath() string     { return c.value.AuditDatabasePath }
func (c *Config) RegistrationKeyID() string     { return c.value.RegistrationKeyID }
func (c *Config) RegistrationPublicKey() string { return c.value.RegistrationPublicKey }
func (c *Config) RequestDeadline() time.Duration {
	return time.Duration(c.value.RequestDeadlineMS) * time.Millisecond
}
func (c *Config) MaxConcurrentRequests() int { return c.value.MaxConcurrentRequests }
func (c *Config) MaxReplayEntries() int      { return c.value.MaxReplayEntries }
func (c *Config) MaxLeaseLifetime() time.Duration {
	return time.Duration(c.value.MaxLeaseLifetimeMS) * time.Millisecond
}
func (c *Config) NATSServerURI() string { return c.value.NATSServerURI }
func (c *Config) NATSConnectTimeout() time.Duration {
	return time.Duration(c.value.NATSConnectTimeoutMS) * time.Millisecond
}
func (c *Config) NATSRequestTimeout() time.Duration {
	return time.Duration(c.value.NATSRequestTimeoutMS) * time.Millisecond
}
func (c *Config) NATSReplicas() int { return c.value.NATSReplicas }
func (c *Config) NATSReplaySafetyWindow() time.Duration {
	return time.Duration(c.value.NATSReplaySafetyWindowMS) * time.Millisecond
}
func (c *Config) NATSRetention() time.Duration {
	return time.Duration(c.value.NATSRetentionMS) * time.Millisecond
}
func (c *Config) CapabilityLimit() int { return c.value.CapabilityLimit }
func (c *Config) CapabilityPendingTTL() time.Duration {
	return time.Duration(c.value.CapabilityPendingTTLMS) * time.Millisecond
}
func (c *Config) Epoch() uint64              { return c.value.Epoch }
func (*Config) String() string               { return "Config{REDACTED}" }
func (*Config) GoString() string             { return "Config{REDACTED}" }
func (*Config) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (s *SecretDescriptors) takeNATSCredential() (int, bool) {
	if s == nil || !s.natsTaken.CompareAndSwap(false, true) {
		return -1, false
	}
	return s.natsCredential, true
}
func (s *SecretDescriptors) takeCapabilityKey() (int, bool) {
	if s == nil || !s.capabilityTaken.CompareAndSwap(false, true) {
		return -1, false
	}
	return s.capabilityKey, true
}
func (*SecretDescriptors) String() string               { return "SecretDescriptors{REDACTED}" }
func (*SecretDescriptors) GoString() string             { return "SecretDescriptors{REDACTED}" }
func (*SecretDescriptors) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func exactHTTPSOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func exactNATSServer(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" || parsed.Host == "" {
		return false
	}
	host, port, splitErr := net.SplitHostPort(parsed.Host)
	ip := net.ParseIP(host)
	parsedPort, portErr := strconv.Atoi(port)
	if splitErr != nil || portErr != nil || parsedPort < 1 || parsedPort > 65535 {
		return false
	}
	return parsed.Scheme == "nats" && ip != nil && ip.IsLoopback() && parsed.String() == value
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
