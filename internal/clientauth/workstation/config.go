// Package workstation defines the closed RFC-0025 workstation bootstrap
// composition. It deliberately contains no Secret Service protocol client,
// token parser, transport default, or ambient dependency discovery.
package workstation

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

	"golang.org/x/sys/unix"
)

const (
	Profile        = "linux-secret-service-v1"
	RootItemSchema = "yukh-coordination/linux-secret-service-root/v1"

	maximumConfigBytes = 8 << 10
)

var ErrInvalidConfiguration = errors.New("workstation bootstrap: invalid configuration")

type configJSON struct {
	Profile                        string `json:"profile"`
	LocalCustodyDatabasePath       string `json:"local_custody_database_path"`
	RelayBaseURI                   string `json:"relay_base_uri"`
	SecretServiceName              string `json:"secret_service_name"`
	SecretServiceCollectionPath    string `json:"secret_service_collection_path"`
	SecretServiceRootItemSchema    string `json:"secret_service_root_item_schema"`
	ConnectionDeadlineMilliseconds int    `json:"connection_deadline_ms"`
	RequestDeadlineMilliseconds    int    `json:"request_deadline_ms"`
	OperationDeadlineMilliseconds  int    `json:"operation_deadline_ms"`
}

// Config is the non-secret, closed workstation identity. It is intentionally
// not serializable or printable because its paths and provider identifiers are
// not public command output.
type Config struct{ value configJSON }

// SecretServiceBinding is the exact provider boundary supplied to an adapter.
type SecretServiceBinding struct {
	name       string
	collection string
	schema     string
}

func (b SecretServiceBinding) Name() string       { return b.name }
func (b SecretServiceBinding) Collection() string { return b.collection }
func (b SecretServiceBinding) RootItemSchema() string {
	return b.schema
}
func (SecretServiceBinding) String() string   { return "SecretServiceBinding{REDACTED}" }
func (SecretServiceBinding) GoString() string { return "SecretServiceBinding{REDACTED}" }

// ParseConfig accepts only the RFC-0025 closed JSON configuration.
func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > maximumConfigBytes || !closedJSONObject(raw) || !uniqueJSONObjectFields(raw) {
		return nil, ErrInvalidConfiguration
	}
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		value.Profile != Profile || !exactAbsolute(value.LocalCustodyDatabasePath) ||
		!exactHTTPSBaseURI(value.RelayBaseURI) || value.SecretServiceName != "org.freedesktop.secrets" ||
		!exactCollectionPath(value.SecretServiceCollectionPath) || value.SecretServiceRootItemSchema != RootItemSchema ||
		!validDeadline(value.ConnectionDeadlineMilliseconds, 5_000) ||
		!validDeadline(value.RequestDeadlineMilliseconds, 15_000) ||
		!validDeadline(value.OperationDeadlineMilliseconds, 30_000) ||
		value.ConnectionDeadlineMilliseconds > value.OperationDeadlineMilliseconds ||
		value.RequestDeadlineMilliseconds > value.OperationDeadlineMilliseconds {
		return nil, ErrInvalidConfiguration
	}
	return &Config{value: value}, nil
}

// LoadConfigFile is the sole file-based configuration entrypoint. It does not
// inspect process environment or follow symlinks.
func LoadConfigFile(path string) (*Config, error) {
	if !exactAbsolute(path) || !securePrivateDirectory(filepath.Dir(path)) {
		return nil, ErrInvalidConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !securePrivateRegular(before) {
		return nil, ErrInvalidConfiguration
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	file := os.NewFile(uintptr(descriptor), "bootstrap-config")
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
	if before.Size() < 1 || before.Size() > maximumConfigBytes {
		return nil, ErrInvalidConfiguration
	}
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

func (c *Config) SecretServiceBinding() SecretServiceBinding {
	if c == nil {
		return SecretServiceBinding{}
	}
	return SecretServiceBinding{name: c.value.SecretServiceName, collection: c.value.SecretServiceCollectionPath, schema: c.value.SecretServiceRootItemSchema}
}

func (c *Config) ConnectionDeadline() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.value.ConnectionDeadlineMilliseconds) * time.Millisecond
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
	info, err := os.Lstat(c.value.LocalCustodyDatabasePath)
	if err == nil && !securePrivateRegular(info) {
		return ErrInvalidConfiguration
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
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

func exactAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func exactHTTPSBaseURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" &&
		!strings.HasSuffix(parsed.Path, "/") && parsed.String() == value
}

func exactCollectionPath(value string) bool {
	const prefix = "/org/freedesktop/secrets/collection/"
	if !strings.HasPrefix(value, prefix) || strings.Contains(value, "//") || strings.Contains(value, "..") {
		return false
	}
	identifier := strings.TrimPrefix(value, prefix)
	if identifier == "" || strings.Contains(identifier, "/") {
		return false
	}
	for index, item := range identifier {
		if !(item >= 'A' && item <= 'Z' || item >= 'a' && item <= 'z' || item >= '0' && item <= '9' || item == '_') ||
			(index == 0 && item >= '0' && item <= '9') {
			return false
		}
	}
	return true
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
