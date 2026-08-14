// Package macosprofile defines the closed RFC-0027 macOS Keychain bootstrap
// composition. It has no Linux, cloud, desktop, or environment selection path.
package macosprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth/keychain"
	"golang.org/x/sys/unix"
)

const (
	Profile = "macos-keychain-v1"

	maximumConfigBytes = 8 << 10
)

var ErrInvalidConfiguration = errors.New("macos keychain bootstrap: invalid configuration")

type configJSON struct {
	Profile                       string `json:"profile"`
	CustodyProfile                string `json:"custody_profile"`
	LocalCustodyDatabasePath      string `json:"local_custody_database_path"`
	RelayBaseURI                  string `json:"relay_base_uri"`
	KeychainPath                  string `json:"keychain_path"`
	KeychainService               string `json:"keychain_service"`
	KeychainAccount               string `json:"keychain_account"`
	KeychainAccessGroup           string `json:"keychain_access_group"`
	RequestDeadlineMilliseconds   int    `json:"request_deadline_ms"`
	OperationDeadlineMilliseconds int    `json:"operation_deadline_ms"`
}

// Config is the non-secret, closed macOS Keychain profile configuration.
// Paths and Keychain metadata are redacted from ordinary formatting.
type Config struct{ value configJSON }

// ParseConfig accepts only RFC-0027 macOS Keychain configuration. The
// Keychain account is exactly the opaque local-custody profile identifier.
func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > maximumConfigBytes || !closedJSONObject(raw) ||
		!uniqueJSONObjectFields(raw) || !hasOnlyFields(raw,
		"profile", "custody_profile", "local_custody_database_path", "relay_base_uri",
		"keychain_path", "keychain_service", "keychain_account", "keychain_access_group",
		"request_deadline_ms", "operation_deadline_ms") {
		return nil, ErrInvalidConfiguration
	}
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		value.Profile != Profile || !exactAbsolute(value.LocalCustodyDatabasePath) ||
		!exactAbsolute(value.KeychainPath) || value.KeychainPath == value.LocalCustodyDatabasePath ||
		!exactHTTPSBaseURI(value.RelayBaseURI) ||
		!validDeadline(value.RequestDeadlineMilliseconds, 15_000) ||
		!validDeadline(value.OperationDeadlineMilliseconds, 30_000) ||
		value.RequestDeadlineMilliseconds > value.OperationDeadlineMilliseconds {
		return nil, ErrInvalidConfiguration
	}
	if _, err := keychain.NewBinding(value.CustodyProfile, value.KeychainService, value.KeychainAccount, value.KeychainAccessGroup, value.KeychainPath); err != nil {
		return nil, ErrInvalidConfiguration
	}
	return &Config{value: value}, nil
}

// LoadConfigFile is the only file-based configuration entrypoint. It rejects
// symlinks, writable paths, and any ambient configuration mechanism.
func LoadConfigFile(path string) (*Config, error) {
	if !exactAbsolute(path) || !securePrivateDirectory(filepath.Dir(path)) {
		return nil, ErrInvalidConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !securePrivateRegular(before) || before.Size() < 1 || before.Size() > maximumConfigBytes {
		return nil, ErrInvalidConfiguration
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(descriptor), "macos-bootstrap-config")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrInvalidConfiguration
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrInvalidConfiguration
	}
	raw := make([]byte, before.Size())
	if count, err := io.ReadFull(file, raw); err != nil || int64(count) != before.Size() {
		return nil, ErrInvalidConfiguration
	}
	after, err = file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, ErrInvalidConfiguration
	}
	config, err := ParseConfig(raw)
	if err != nil || config.ValidatePaths() != nil || path == config.value.LocalCustodyDatabasePath {
		return nil, ErrInvalidConfiguration
	}
	return config, nil
}

func (c *Config) Profile() string {
	if c == nil {
		return ""
	}
	return c.value.Profile
}

func (c *Config) CustodyProfile() string {
	if c == nil {
		return ""
	}
	return c.value.CustodyProfile
}

func (c *Config) LocalCustodyDatabasePath() string {
	if c == nil {
		return ""
	}
	return c.value.LocalCustodyDatabasePath
}

func (c *Config) RelayBaseURI() string {
	if c == nil {
		return ""
	}
	return c.value.RelayBaseURI
}

func (c *Config) KeychainPath() string {
	if c == nil {
		return ""
	}
	return c.value.KeychainPath
}

func (c *Config) KeychainBinding() (keychain.Binding, error) {
	if c == nil {
		return keychain.Binding{}, ErrInvalidConfiguration
	}
	binding, err := keychain.NewBinding(c.value.CustodyProfile, c.value.KeychainService, c.value.KeychainAccount, c.value.KeychainAccessGroup, c.value.KeychainPath)
	if err != nil {
		return keychain.Binding{}, ErrInvalidConfiguration
	}
	return binding, nil
}

func (c *Config) RequestDeadline() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.value.RequestDeadlineMilliseconds) * time.Millisecond
}

func (c *Config) OperationDeadline() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.value.OperationDeadlineMilliseconds) * time.Millisecond
}

func (c *Config) ValidatePaths() error {
	if c == nil || !securePrivateDirectory(filepath.Dir(c.value.LocalCustodyDatabasePath)) {
		return ErrInvalidConfiguration
	}
	if _, err := c.KeychainBinding(); err != nil {
		return ErrInvalidConfiguration
	}
	database, err := os.Lstat(c.value.LocalCustodyDatabasePath)
	if err == nil && !securePrivateRegular(database) {
		return ErrInvalidConfiguration
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidConfiguration
	}
	keychainInfo, err := os.Lstat(c.value.KeychainPath)
	if err != nil || !securePrivateRegular(keychainInfo) ||
		(database != nil && os.SameFile(database, keychainInfo)) {
		return ErrInvalidConfiguration
	}
	return nil
}

func (*Config) String() string   { return "Config{REDACTED}" }
func (*Config) GoString() string { return "Config{REDACTED}" }
func (*Config) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidConfiguration
}

func closedJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 1 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func uniqueJSONObjectFields(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	fields := make(map[string]struct{})
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return false
		}
		if _, exists := fields[name]; exists {
			return false
		}
		fields[name] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}')
}

func hasOnlyFields(raw []byte, expected ...string) bool {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil || len(values) != len(expected) {
		return false
	}
	for _, name := range expected {
		if _, exists := values[name]; !exists {
			return false
		}
	}
	return true
}

func exactAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func exactHTTPSBaseURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" &&
		!strings.HasSuffix(parsed.Path, "/") && parsed.String() == value
}

func validDeadline(value, maximum int) bool {
	return value >= 1 && value <= maximum
}

func securePrivateRegular(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0 && ownedByEffectiveUser(info)
}

func securePrivateDirectory(path string) bool {
	if !exactAbsolute(path) {
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
