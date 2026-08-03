package primitivesstaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"golang.org/x/sys/unix"
)

const (
	capabilityKeyringProfile  = "yukh-coordination/private-primitives-capability-keyring/v1"
	maxCapabilityKeyringBytes = 4096
)

type CapabilityKeyLifecycleAudit interface {
	RecordCapabilityKeyLifecycle(context.Context, bool) error
}

type capabilityKeyJSON struct {
	KeyID        string          `json:"key_id"`
	Key          json.RawMessage `json:"key"`
	SealFrom     string          `json:"seal_from"`
	SealUntil    string          `json:"seal_until"`
	DecryptUntil string          `json:"decrypt_until"`
}

type capabilityKeyringJSON struct {
	Profile string              `json:"profile"`
	Keys    []capabilityKeyJSON `json:"keys"`
}

type heldCapabilityKey struct {
	id           string
	material     []byte
	sealFrom     time.Time
	sealUntil    time.Time
	decryptUntil time.Time
	locked       bool
}

type CapabilityKeyring struct {
	mu     sync.RWMutex
	keys   []heldCapabilityKey
	active int
	now    func() time.Time
	audit  CapabilityKeyLifecycleAudit
	closed bool
}

func OpenCapabilityKeyring(ctx context.Context, descriptors *SecretDescriptors, maxLeaseLifetime time.Duration, now func() time.Time, lifecycleAudit CapabilityKeyLifecycleAudit) (*CapabilityKeyring, error) {
	if ctx == nil || descriptors == nil || maxLeaseLifetime <= 0 || maxLeaseLifetime > 15*time.Minute || now == nil || lifecycleAudit == nil {
		return nil, ErrInvalid
	}
	descriptor, ok := descriptors.takeCapabilityKey()
	if !ok {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(descriptor), "capability-key")
	if file == nil {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCapabilityKeyringBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) == 0 || len(raw) > maxCapabilityKeyringBytes {
		clear(raw)
		return nil, ErrUnavailable
	}
	defer clear(raw)
	keyring, err := parseCapabilityKeyring(raw, maxLeaseLifetime, now)
	if err != nil {
		return nil, err
	}
	keyring.audit = lifecycleAudit
	if err := lifecycleAudit.RecordCapabilityKeyLifecycle(ctx, true); err != nil {
		keyring.zeroLocked()
		return nil, ErrUnavailable
	}
	return keyring, nil
}

func parseCapabilityKeyring(raw []byte, maxLeaseLifetime time.Duration, now func() time.Time) (*CapabilityKeyring, error) {
	if maxLeaseLifetime <= 0 || maxLeaseLifetime > 15*time.Minute || now == nil || !closedJSONObject(raw) {
		return nil, ErrInvalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalid
	}
	var value capabilityKeyringJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Profile != capabilityKeyringProfile || len(value.Keys) < 1 || len(value.Keys) > 2 {
		clearEncodedCapabilityKeys(value.Keys)
		return nil, ErrInvalid
	}
	defer clearEncodedCapabilityKeys(value.Keys)
	observed := now().UTC().Truncate(time.Millisecond)
	if !validMillisecond(observed) {
		return nil, ErrUnavailable
	}
	result := &CapabilityKeyring{active: -1, now: now, keys: make([]heldCapabilityKey, 0, len(value.Keys))}
	seen := map[string]struct{}{}
	for _, encoded := range value.Keys {
		if !opaque(encoded.KeyID, 128) {
			result.zeroLocked()
			return nil, ErrInvalid
		}
		if _, exists := seen[encoded.KeyID]; exists {
			result.zeroLocked()
			return nil, ErrInvalid
		}
		seen[encoded.KeyID] = struct{}{}
		material, decodeErr := decodeCapabilityKey(encoded.Key)
		sealFrom, fromErr := parseKeyTime(encoded.SealFrom)
		sealUntil, untilErr := parseKeyTime(encoded.SealUntil)
		decryptUntil, decryptErr := parseKeyTime(encoded.DecryptUntil)
		if decodeErr != nil || len(material) != 32 || fromErr != nil || untilErr != nil || decryptErr != nil || !sealUntil.After(sealFrom) || decryptUntil.Sub(sealUntil) != maxLeaseLifetime || sealUntil.Sub(sealFrom) > 24*time.Hour || !decryptUntil.After(observed) {
			clear(material)
			result.zeroLocked()
			return nil, ErrInvalid
		}
		held := heldCapabilityKey{id: encoded.KeyID, material: material, sealFrom: sealFrom, sealUntil: sealUntil, decryptUntil: decryptUntil}
		if unix.Mlock(held.material) == nil {
			held.locked = true
		}
		if !observed.Before(sealFrom) && observed.Before(sealUntil) {
			if result.active != -1 {
				if held.locked {
					_ = unix.Munlock(held.material)
				}
				clear(held.material)
				result.zeroLocked()
				return nil, ErrInvalid
			}
			result.active = len(result.keys)
		} else if observed.Before(sealFrom) {
			if held.locked {
				_ = unix.Munlock(held.material)
			}
			clear(held.material)
			result.zeroLocked()
			return nil, ErrInvalid
		}
		result.keys = append(result.keys, held)
	}
	if result.active == -1 || sealWindowsOverlap(result.keys) {
		result.zeroLocked()
		return nil, ErrInvalid
	}
	return result, nil
}

func decodeCapabilityKey(encoded json.RawMessage) ([]byte, error) {
	if len(encoded) != 45 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return nil, ErrInvalid
	}
	material := make([]byte, 32)
	written, err := base64.RawURLEncoding.Strict().Decode(material, encoded[1:len(encoded)-1])
	if err != nil || written != len(material) {
		clear(material)
		return nil, ErrInvalid
	}
	return material, nil
}

func clearEncodedCapabilityKeys(keys []capabilityKeyJSON) {
	for index := range keys {
		clear(keys[index].Key)
		keys[index].Key = nil
	}
}

func (r *CapabilityKeyring) Active(_ context.Context) (primitives.SealingKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.readyLocked() {
		return primitives.SealingKey{}, primitives.ErrUnavailable
	}
	key, err := primitives.NewSealingKey(r.keys[r.active].id, r.keys[r.active].material)
	if err != nil {
		return primitives.SealingKey{}, primitives.ErrUnavailable
	}
	return key, nil
}

func (r *CapabilityKeyring) Open(_ context.Context, keyID string) (primitives.SealingKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !opaque(keyID, 128) {
		return primitives.SealingKey{}, primitives.ErrUnavailable
	}
	observed := r.now().UTC().Truncate(time.Millisecond)
	for _, held := range r.keys {
		if held.id == keyID && observed.Before(held.decryptUntil) {
			key, err := primitives.NewSealingKey(held.id, held.material)
			if err != nil {
				return primitives.SealingKey{}, primitives.ErrUnavailable
			}
			return key, nil
		}
	}
	return primitives.SealingKey{}, primitives.ErrUnavailable
}

func (r *CapabilityKeyring) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.readyLocked()
}

func (r *CapabilityKeyring) Close(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.zeroLocked()
	audit := r.audit
	r.mu.Unlock()
	if audit == nil || audit.RecordCapabilityKeyLifecycle(ctx, false) != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *CapabilityKeyring) readyLocked() bool {
	if r == nil || r.closed || r.active < 0 || r.active >= len(r.keys) || r.now == nil {
		return false
	}
	now := r.now().UTC().Truncate(time.Millisecond)
	active := r.keys[r.active]
	return validMillisecond(now) && !now.Before(active.sealFrom) && now.Before(active.sealUntil) && now.Before(active.decryptUntil) && len(active.material) == 32
}

func (r *CapabilityKeyring) zeroLocked() {
	for index := range r.keys {
		clear(r.keys[index].material)
		if r.keys[index].locked {
			_ = unix.Munlock(r.keys[index].material)
			r.keys[index].locked = false
		}
		r.keys[index].material = nil
	}
}

func parseKeyTime(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil || parsed.Format("2006-01-02T15:04:05.000Z") != value {
		return time.Time{}, errors.New("invalid key time")
	}
	return parsed, nil
}

func sealWindowsOverlap(keys []heldCapabilityKey) bool {
	return len(keys) == 2 && keys[0].sealFrom.Before(keys[1].sealUntil) && keys[1].sealFrom.Before(keys[0].sealUntil)
}

func (*CapabilityKeyring) String() string               { return "CapabilityKeyring{REDACTED}" }
func (*CapabilityKeyring) GoString() string             { return "CapabilityKeyring{REDACTED}" }
func (*CapabilityKeyring) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
