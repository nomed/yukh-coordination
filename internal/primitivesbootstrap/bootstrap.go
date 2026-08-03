// Package primitivesbootstrap implements the separately gated RFC-0022
// one-shot JetStream bucket bootstrap operation. It provisions no server,
// credential, listener or consumer traffic.
package primitivesbootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nomed/yukh-coordination/internal/coordination/jetstreamkv"
	"golang.org/x/sys/unix"
)

const (
	Profile                  = "yukh-coordination/private-primitives-staging-bootstrap-v1"
	maxConfigBytes           = 16 << 10
	maxNATSCredentialBytes   = 16 << 10
	credentialCopyDescriptor = 64
)

var (
	ErrInvalid     = errors.New("private primitives bootstrap: invalid")
	ErrUnavailable = errors.New("private primitives bootstrap: unavailable")
)

type configJSON struct {
	Profile                  string `json:"profile"`
	NATSServerURI            string `json:"nats_server_uri"`
	NATSConnectTimeoutMS     int    `json:"nats_connect_timeout_ms"`
	NATSRequestTimeoutMS     int    `json:"nats_request_timeout_ms"`
	NATSReplicas             int    `json:"nats_replicas"`
	NATSReplaySafetyWindowMS int    `json:"nats_replay_safety_window_ms"`
	NATSRetentionMS          int    `json:"nats_retention_ms"`
	MaxLeaseLifetimeMS       int    `json:"max_lease_lifetime_ms"`
	CapabilityLimit          int    `json:"capability_limit"`
	CapabilityPendingTTLMS   int    `json:"capability_pending_ttl_ms"`
	Epoch                    uint64 `json:"epoch"`
}

type Config struct{ value configJSON }

func ParseConfig(raw []byte) (*Config, error) {
	if len(raw) == 0 || len(raw) > maxConfigBytes || !closedObject(raw) {
		return nil, ErrInvalid
	}
	var value configJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Profile != Profile || !loopbackNATS(value.NATSServerURI) ||
		value.NATSConnectTimeoutMS < 1 || value.NATSConnectTimeoutMS > 5_000 ||
		value.NATSRequestTimeoutMS < 1 || value.NATSRequestTimeoutMS > 5_000 ||
		value.NATSReplicas < 1 || value.NATSReplicas > 5 ||
		value.MaxLeaseLifetimeMS < 1 || value.MaxLeaseLifetimeMS > 900_000 ||
		value.NATSReplaySafetyWindowMS < value.MaxLeaseLifetimeMS || value.NATSReplaySafetyWindowMS > 86_400_000 ||
		value.NATSRetentionMS <= value.MaxLeaseLifetimeMS+value.NATSReplaySafetyWindowMS || value.NATSRetentionMS > 604_800_000 ||
		value.CapabilityLimit < 1 || value.CapabilityLimit > 32 ||
		value.CapabilityPendingTTLMS < 1 || value.CapabilityPendingTTLMS > value.NATSRequestTimeoutMS ||
		value.Epoch == 0 || value.Epoch > 9_007_199_254_740_991 {
		return nil, ErrInvalid
	}
	return &Config{value: value}, nil
}

func LoadConfigFile(path string) (*Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !secureRegular(path) {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) > maxConfigBytes {
		return nil, ErrInvalid
	}
	return ParseConfig(raw)
}

func (config *Config) storeConfig() jetstreamkv.Config {
	return jetstreamkv.Config{
		Replicas: config.value.NATSReplicas, Bootstrap: true,
		MaxLifetime:        time.Duration(config.value.MaxLeaseLifetimeMS) * time.Millisecond,
		ReplaySafetyWindow: time.Duration(config.value.NATSReplaySafetyWindowMS) * time.Millisecond,
		Retention:          time.Duration(config.value.NATSRetentionMS) * time.Millisecond,
		Epoch:              config.value.Epoch,
	}
}

type CredentialDescriptor struct {
	value int
	taken atomic.Bool
}

func CaptureCredentialDescriptor(value int) (*CredentialDescriptor, error) {
	if value < 3 {
		return nil, ErrInvalid
	}
	copy, copyErr := unix.FcntlInt(uintptr(value), unix.F_DUPFD_CLOEXEC, credentialCopyDescriptor)
	closeErr := unix.Close(value)
	if copyErr != nil || closeErr != nil {
		if copyErr == nil {
			_ = unix.Close(copy)
		}
		return nil, ErrUnavailable
	}
	return &CredentialDescriptor{value: copy}, nil
}

func (descriptor *CredentialDescriptor) take() (int, bool) {
	if descriptor == nil || !descriptor.taken.CompareAndSwap(false, true) {
		return -1, false
	}
	return descriptor.value, true
}

func (descriptor *CredentialDescriptor) Close() error {
	if descriptor == nil {
		return ErrInvalid
	}
	if !descriptor.taken.Swap(true) && unix.Close(descriptor.value) != nil {
		return ErrUnavailable
	}
	return nil
}

type Receipt struct {
	Schema        int    `json:"schema"`
	Profile       string `json:"profile"`
	Revision      string `json:"revision"`
	Epoch         uint64 `json:"epoch"`
	BucketProfile string `json:"bucket_profile_sha256"`
	Outcome       string `json:"outcome"`
}

func (receipt Receipt) Bytes() ([]byte, error) {
	if receipt.Schema != 1 || receipt.Profile != Profile || !revision(receipt.Revision) || receipt.Epoch == 0 || len(receipt.BucketProfile) != 64 || receipt.Outcome != "verified" {
		return nil, ErrInvalid
	}
	for _, character := range receipt.BucketProfile {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return nil, ErrInvalid
		}
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, ErrUnavailable
	}
	return append(raw, '\n'), nil
}

type opener func(context.Context, *Config, []byte) error

func Run(ctx context.Context, path string, descriptor *CredentialDescriptor, buildRevision string) (Receipt, error) {
	return run(ctx, path, descriptor, buildRevision, openBuckets)
}

func run(ctx context.Context, path string, descriptor *CredentialDescriptor, buildRevision string, open opener) (Receipt, error) {
	if ctx == nil || descriptor == nil || open == nil || !revision(buildRevision) {
		return Receipt{}, ErrInvalid
	}
	config, err := LoadConfigFile(path)
	if err != nil {
		return Receipt{}, ErrInvalid
	}
	fd, ok := descriptor.take()
	if !ok {
		return Receipt{}, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), "nats-bootstrap-credential")
	if file == nil {
		return Receipt{}, ErrUnavailable
	}
	credential, readErr := io.ReadAll(io.LimitReader(file, maxNATSCredentialBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(credential) == 0 || len(credential) > maxNATSCredentialBytes {
		clear(credential)
		return Receipt{}, ErrUnavailable
	}
	_ = unix.Mlock(credential)
	defer func() {
		clear(credential)
		_ = unix.Munlock(credential)
	}()
	if open(ctx, config, credential) != nil {
		return Receipt{}, ErrUnavailable
	}
	return Receipt{Schema: 1, Profile: Profile, Revision: buildRevision, Epoch: config.value.Epoch, BucketProfile: config.profileDigest(), Outcome: "verified"}, nil
}

func openBuckets(ctx context.Context, config *Config, credential []byte) error {
	connection, err := nats.Connect(config.value.NATSServerURI,
		nats.Name("yukh-coordination-private-primitives-bootstrap-v1"),
		nats.UserCredentialBytes(credential), nats.Timeout(time.Duration(config.value.NATSConnectTimeoutMS)*time.Millisecond),
		nats.NoReconnect(), nats.NoEcho())
	if err != nil {
		return ErrUnavailable
	}
	defer connection.Close()
	return bootstrapStores(ctx, config, connection)
}

func bootstrapStores(ctx context.Context, config *Config, connection *nats.Conn) error {
	if ctx == nil || config == nil || connection == nil || !connection.IsConnected() {
		return ErrInvalid
	}
	requestContext, cancel := context.WithTimeout(ctx, time.Duration(config.value.NATSRequestTimeoutMS)*time.Millisecond)
	defer cancel()
	storeConfig := config.storeConfig()
	stores, err := jetstreamkv.Open(requestContext, connection, storeConfig)
	if err != nil {
		return ErrUnavailable
	}
	budget, err := jetstreamkv.OpenCapabilityBudget(requestContext, connection, storeConfig, config.value.CapabilityLimit, time.Duration(config.value.CapabilityPendingTTLMS)*time.Millisecond)
	if err != nil || stores.Probe(requestContext) != nil || budget.Probe(requestContext) != nil {
		return ErrUnavailable
	}
	return nil
}

func (config *Config) profileDigest() string {
	profile := struct {
		Buckets         []string `json:"buckets"`
		Replicas        int      `json:"replicas"`
		MaxLifetimeMS   int      `json:"max_lifetime_ms"`
		ReplaySafetyMS  int      `json:"replay_safety_ms"`
		RetentionMS     int      `json:"retention_ms"`
		CapabilityLimit int      `json:"capability_limit"`
		CapabilityTTLMS int      `json:"capability_pending_ttl_ms"`
		Epoch           uint64   `json:"epoch"`
	}{[]string{jetstreamkv.NonceBucket, jetstreamkv.LeaseBucket, jetstreamkv.CapabilityBudgetBucket}, config.value.NATSReplicas, config.value.MaxLeaseLifetimeMS, config.value.NATSReplaySafetyWindowMS, config.value.NATSRetentionMS, config.value.CapabilityLimit, config.value.CapabilityPendingTTLMS, config.value.Epoch}
	raw, _ := json.Marshal(profile)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func revision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func loopbackNATS(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "nats" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value {
		return false
	}
	host, port, splitErr := net.SplitHostPort(parsed.Host)
	number, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	return splitErr == nil && portErr == nil && number > 0 && number <= 65535 && ip != nil && ip.IsLoopback()
}

func secureRegular(path string) bool {
	current := filepath.Clean(path)
	for current != string(filepath.Separator) {
		current = filepath.Dir(current)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0
}

func closedObject(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		nameToken, nameErr := decoder.Token()
		name, ok := nameToken.(string)
		if nameErr != nil || !ok || name == "" {
			return false
		}
		folded := strings.ToLower(name)
		if _, duplicate := seen[folded]; duplicate {
			return false
		}
		seen[folded] = struct{}{}
		value, valueErr := decoder.Token()
		if valueErr != nil {
			return false
		}
		if _, nested := value.(json.Delim); nested {
			return false
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func (*Config) String() string                             { return "Config{REDACTED}" }
func (*Config) GoString() string                           { return "Config{REDACTED}" }
func (*Config) MarshalJSON() ([]byte, error)               { return nil, ErrInvalid }
func (*CredentialDescriptor) String() string               { return "CredentialDescriptor{REDACTED}" }
func (*CredentialDescriptor) GoString() string             { return "CredentialDescriptor{REDACTED}" }
func (*CredentialDescriptor) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
