// Package jetstreamkv implements RFC-0012 without changing the relay adapter.
package jetstreamkv

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/coordination"
)

const (
	NonceBucket   = "YUKH_COORDINATION_NONCES_V1"
	LeaseBucket   = "YUKH_COORDINATION_LEASES_V1"
	maxValueBytes = int32(1024)
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Config struct {
	Replicas           int
	Bootstrap          bool
	MaxLifetime        time.Duration
	ReplaySafetyWindow time.Duration
	Retention          time.Duration
	Epoch              uint64
}

type atomicKV interface {
	Create(context.Context, string, []byte, ...natsjs.KVCreateOpt) (uint64, error)
	Get(context.Context, string) (natsjs.KeyValueEntry, error)
	Update(context.Context, string, []byte, uint64) (uint64, error)
}

type Store struct {
	nonces atomicKV
	leases atomicKV
	config Config
	now    func() time.Time
}

func (store *Store) ConfiguredEpoch() uint64 { return store.config.Epoch }

type value struct {
	Schema    int    `json:"schema"`
	Kind      string `json:"kind"`
	Digest    string `json:"digest"`
	ExpiresAt string `json:"expires_at"`
	Epoch     uint64 `json:"epoch"`
	Released  bool   `json:"released"`
}

func expected(bucket, description string, config Config) natsjs.KeyValueConfig {
	return natsjs.KeyValueConfig{
		Bucket:       bucket,
		Description:  description,
		MaxValueSize: maxValueBytes,
		History:      64,
		TTL:          config.Retention,
		Storage:      natsjs.FileStorage,
		Replicas:     config.Replicas,
		Metadata: map[string]string{
			"yukh.adapter":         "coordination-kv",
			"yukh.adapter.version": "1",
			"yukh.epoch":           strconv.FormatUint(config.Epoch, 10),
		},
	}
}

func Open(ctx context.Context, connection *nats.Conn, config Config) (*Store, error) {
	if connection == nil || config.Replicas < 1 || config.Replicas > 5 || config.MaxLifetime <= 0 || config.ReplaySafetyWindow <= 0 || config.Retention <= config.MaxLifetime || config.Retention-config.MaxLifetime <= config.ReplaySafetyWindow || config.Epoch == 0 {
		return nil, coordination.ErrInvalidArgument
	}
	js, err := natsjs.New(connection)
	if err != nil {
		return nil, coordination.ErrUnavailable
	}
	open := func(expectedConfig natsjs.KeyValueConfig) (natsjs.KeyValue, error) {
		kv, openErr := js.KeyValue(ctx, expectedConfig.Bucket)
		if errors.Is(openErr, natsjs.ErrBucketNotFound) && config.Bootstrap {
			kv, openErr = js.CreateKeyValue(ctx, expectedConfig)
		}
		if openErr != nil {
			return nil, coordination.ErrUnavailable
		}
		status, statusErr := kv.Status(ctx)
		if statusErr != nil {
			return nil, coordination.ErrUnavailable
		}
		if !matchingStatus(status, expectedConfig) {
			return nil, coordination.ErrInvalidArgument
		}
		return kv, nil
	}
	nonces, err := open(expected(NonceBucket, "Yukh external nonce replay protection", config))
	if err != nil {
		return nil, err
	}
	leases, err := open(expected(LeaseBucket, "Yukh external fenced leases", config))
	if err != nil {
		return nil, err
	}
	return &Store{nonces: nonces, leases: leases, config: config, now: time.Now}, nil
}

func matchingStatus(status natsjs.KeyValueStatus, expectedConfig natsjs.KeyValueConfig) bool {
	metadata := status.Metadata()
	if status.Bucket() != expectedConfig.Bucket || !matchingMetadata(metadata, expectedConfig.Metadata) ||
		status.History() != int64(expectedConfig.History) ||
		status.TTL() != expectedConfig.TTL ||
		metadata["yukh.adapter"] != expectedConfig.Metadata["yukh.adapter"] ||
		metadata["yukh.adapter.version"] != expectedConfig.Metadata["yukh.adapter.version"] ||
		metadata["yukh.epoch"] != expectedConfig.Metadata["yukh.epoch"] {
		return false
	}
	withInfo, ok := status.(interface{ StreamInfo() *natsjs.StreamInfo })
	if !ok || withInfo.StreamInfo() == nil {
		return false
	}
	config := withInfo.StreamInfo().Config
	return config.Name == "KV_"+expectedConfig.Bucket &&
		config.Description == expectedConfig.Description &&
		len(config.Subjects) == 1 && config.Subjects[0] == "$KV."+expectedConfig.Bucket+".>" &&
		config.Retention == natsjs.LimitsPolicy && config.Discard == natsjs.DiscardNew &&
		config.MaxConsumers == -1 && config.MaxMsgs == -1 && config.MaxBytes == -1 &&
		config.MaxMsgsPerSubject == int64(expectedConfig.History) &&
		config.MaxAge == expectedConfig.TTL &&
		config.MaxMsgSize == expectedConfig.MaxValueSize &&
		config.Storage == expectedConfig.Storage &&
		config.Replicas == expectedConfig.Replicas &&
		!config.NoAck && config.DenyDelete && !config.DenyPurge && config.AllowRollup && config.AllowDirect &&
		config.Placement == nil && config.Mirror == nil && len(config.Sources) == 0 && config.RePublish == nil &&
		!config.Sealed && !config.MirrorDirect && config.SubjectTransform == nil && !config.AllowMsgTTL && config.SubjectDeleteMarkerTTL == 0
}

func matchingMetadata(observed, expected map[string]string) bool {
	for key, value := range expected {
		if observed[key] != value {
			return false
		}
	}
	for key := range observed {
		if _, owned := expected[key]; !owned && !strings.HasPrefix(key, "_nats.") {
			return false
		}
	}
	return true
}

func validDigest(candidate coordination.Digest) bool {
	return digestPattern.MatchString(string(candidate))
}

func (store *Store) validExpiry(expires time.Time) bool {
	now := store.now().UTC()
	return expires.After(now) && !expires.After(now.Add(store.config.MaxLifetime))
}

func encode(kind string, digest coordination.Digest, expires time.Time, epoch uint64, released bool) ([]byte, error) {
	return json.Marshal(value{Schema: 1, Kind: kind, Digest: string(digest), ExpiresAt: expires.UTC().Format(time.RFC3339Nano), Epoch: epoch, Released: released})
}

func decode(raw []byte) (value, error) {
	var decoded value
	if len(raw) == 0 || len(raw) > int(maxValueBytes) {
		return decoded, coordination.ErrConflict
	}
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.Schema != 1 {
		return decoded, coordination.ErrConflict
	}
	return decoded, nil
}

func exact(observed value, kind string, digest coordination.Digest, expires time.Time, epoch uint64, released bool) bool {
	return observed.Kind == kind && observed.Digest == string(digest) && observed.ExpiresAt == expires.UTC().Format(time.RFC3339Nano) && observed.Epoch == epoch && observed.Released == released
}

func (store *Store) Consume(ctx context.Context, key coordination.Digest, nonce coordination.NonceValue) (coordination.NonceOutcome, error) {
	if !validDigest(key) || !validDigest(nonce.ValueDigest) || nonce.Epoch != store.config.Epoch || !store.validExpiry(nonce.ExpiresAt) {
		return "", coordination.ErrInvalidArgument
	}
	raw, err := encode("nonce", nonce.ValueDigest, nonce.ExpiresAt, nonce.Epoch, false)
	if err != nil {
		return "", coordination.ErrInvalidArgument
	}
	_, err = store.nonces.Create(ctx, string(key), raw)
	if err == nil {
		return coordination.NonceConsumed, nil
	}
	if errors.Is(err, natsjs.ErrKeyExists) {
		return coordination.NonceReplayed, nil
	}
	// A timed-out create may have committed. Reconcile only an exact value.
	entry, getErr := store.nonces.Get(ctx, string(key))
	if getErr != nil {
		return "", coordination.ErrUnavailable
	}
	observed, decodeErr := decode(entry.Value())
	if decodeErr != nil || !exact(observed, "nonce", nonce.ValueDigest, nonce.ExpiresAt, nonce.Epoch, false) {
		return "", coordination.ErrConflict
	}
	return coordination.NonceConsumed, nil
}

type lease struct {
	store    *Store
	key      coordination.Digest
	holder   coordination.Digest
	expires  time.Time
	mu       sync.Mutex
	revision uint64
	released bool
}

func (store *Store) Acquire(ctx context.Context, key coordination.Digest, candidate coordination.LeaseValue) (coordination.Lease, error) {
	if !validDigest(key) || !validDigest(candidate.HolderDigest) || candidate.Epoch != store.config.Epoch || !store.validExpiry(candidate.ExpiresAt) {
		return nil, coordination.ErrInvalidArgument
	}
	raw, err := encode("lease", candidate.HolderDigest, candidate.ExpiresAt, candidate.Epoch, false)
	if err != nil {
		return nil, coordination.ErrInvalidArgument
	}
	revision, err := store.leases.Create(ctx, string(key), raw)
	if err == nil {
		return store.newLease(key, candidate, revision), nil
	}
	entry, getErr := store.leases.Get(ctx, string(key))
	if getErr != nil {
		return nil, coordination.ErrUnavailable
	}
	observed, decodeErr := decode(entry.Value())
	if decodeErr != nil || observed.Kind != "lease" || observed.Epoch != store.config.Epoch {
		return nil, coordination.ErrConflict
	}
	// Reconcile an ambiguous successful create, but never turn ErrKeyExists
	// into ownership: an exact retry is still a competing acquisition.
	if !errors.Is(err, natsjs.ErrKeyExists) && exact(observed, "lease", candidate.HolderDigest, candidate.ExpiresAt, candidate.Epoch, false) {
		return store.newLease(key, candidate, entry.Revision()), nil
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, observed.ExpiresAt)
	if parseErr != nil {
		return nil, coordination.ErrConflict
	}
	if !observed.Released && expires.After(store.now().UTC()) {
		return nil, coordination.ErrConflict
	}
	revision, err = store.leases.Update(ctx, string(key), raw, entry.Revision())
	if err != nil {
		revision, err = store.reconcileLeaseMutation(ctx, key, raw, entry.Revision())
		if err != nil {
			return nil, err
		}
	}
	return store.newLease(key, candidate, revision), nil
}

func (store *Store) reconcileLeaseMutation(ctx context.Context, key coordination.Digest, expectedRaw []byte, previousRevision uint64) (uint64, error) {
	entry, err := store.leases.Get(ctx, string(key))
	if err != nil {
		return 0, coordination.ErrUnavailable
	}
	if entry.Revision() <= previousRevision || string(entry.Value()) != string(expectedRaw) {
		return 0, coordination.ErrConflict
	}
	return entry.Revision(), nil
}

func (store *Store) newLease(key coordination.Digest, candidate coordination.LeaseValue, revision uint64) *lease {
	return &lease{store: store, key: key, holder: candidate.HolderDigest, expires: candidate.ExpiresAt, revision: revision}
}

func (store *Store) Resume(ctx context.Context, key coordination.Digest, resume coordination.LeaseResumeValue) (coordination.Lease, error) {
	if !validDigest(key) || resume.Epoch() != store.config.Epoch {
		return nil, coordination.ErrInvalidArgument
	}
	entry, err := store.leases.Get(ctx, string(key))
	if errors.Is(err, natsjs.ErrKeyNotFound) || errors.Is(err, natsjs.ErrKeyDeleted) {
		return nil, coordination.ErrConflict
	}
	if err != nil {
		return nil, coordination.ErrUnavailable
	}
	observed, err := decode(entry.Value())
	if err != nil || observed.Kind != "lease" || observed.Released || observed.Digest != string(resume.HolderDigest()) ||
		observed.ExpiresAt != resume.ExpiresAt().Format(time.RFC3339Nano) || observed.Epoch != resume.Epoch() ||
		entry.Revision() != resume.FencingToken() || !resume.ExpiresAt().After(store.now().UTC()) {
		return nil, coordination.ErrConflict
	}
	return &lease{store: store, key: key, holder: resume.HolderDigest(), expires: resume.ExpiresAt(), revision: resume.FencingToken()}, nil
}

func (store *Store) Inspect(ctx context.Context, key coordination.Digest, resume coordination.LeaseResumeValue) (coordination.LeaseStatus, error) {
	if !validDigest(key) || resume.Epoch() != store.config.Epoch {
		return "", coordination.ErrInvalidArgument
	}
	entry, err := store.leases.Get(ctx, string(key))
	if errors.Is(err, natsjs.ErrKeyNotFound) || errors.Is(err, natsjs.ErrKeyDeleted) {
		return coordination.LeaseStale, nil
	}
	if err != nil {
		return "", coordination.ErrUnavailable
	}
	observed, err := decode(entry.Value())
	if err != nil || observed.Kind != "lease" {
		return "", coordination.ErrUnavailable
	}
	if observed.Digest != string(resume.HolderDigest()) || observed.ExpiresAt != resume.ExpiresAt().Format(time.RFC3339Nano) || observed.Epoch != resume.Epoch() {
		return coordination.LeaseStale, nil
	}
	if observed.Released && resume.FencingToken() < ^uint64(0) && entry.Revision() == resume.FencingToken()+1 {
		return coordination.LeaseReleased, nil
	}
	if observed.Released || entry.Revision() != resume.FencingToken() {
		return coordination.LeaseStale, nil
	}
	if !resume.ExpiresAt().After(store.now().UTC()) {
		return coordination.LeaseExpired, nil
	}
	return coordination.LeaseValid, nil
}

func (held *lease) FencingToken() uint64 {
	held.mu.Lock()
	defer held.mu.Unlock()
	return held.revision
}

func (held *lease) Renew(ctx context.Context, expires time.Time) error {
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.released || !held.store.validExpiry(expires) {
		return coordination.ErrConflict
	}
	raw, err := encode("lease", held.holder, expires, held.store.config.Epoch, false)
	if err != nil {
		return coordination.ErrInvalidArgument
	}
	revision, err := held.store.leases.Update(ctx, string(held.key), raw, held.revision)
	if err != nil {
		revision, err = held.store.reconcileLeaseMutation(ctx, held.key, raw, held.revision)
		if err != nil {
			return err
		}
	}
	held.revision, held.expires = revision, expires
	return nil
}

func (held *lease) Valid(ctx context.Context) (bool, error) {
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.released || !held.expires.After(held.store.now().UTC()) {
		return false, nil
	}
	entry, err := held.store.leases.Get(ctx, string(held.key))
	if err != nil {
		return false, coordination.ErrUnavailable
	}
	return entry.Revision() == held.revision, nil
}

func (held *lease) Release(ctx context.Context) error {
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.released {
		return coordination.ErrConflict
	}
	raw, err := encode("lease", held.holder, held.expires, held.store.config.Epoch, true)
	if err != nil {
		return coordination.ErrInvalidArgument
	}
	revision, err := held.store.leases.Update(ctx, string(held.key), raw, held.revision)
	if err != nil {
		revision, err = held.store.reconcileLeaseMutation(ctx, held.key, raw, held.revision)
		if err != nil {
			return err
		}
	}
	held.revision, held.released = revision, true
	return nil
}
