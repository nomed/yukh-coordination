package primitives

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"time"

	"github.com/nomed/yukh-coordination/internal/coordination"
)

const capabilityPlaintextBytes = 168

type SealingKey struct {
	id    string
	bytes [32]byte
}

func NewSealingKey(id string, raw []byte) (SealingKey, error) {
	if !validIdentifier(id) || len(raw) != 32 {
		return SealingKey{}, ErrInvalidArgument
	}
	var key SealingKey
	key.id = id
	copy(key.bytes[:], raw)
	return key, nil
}

func (SealingKey) String() string   { return "SealingKey{REDACTED}" }
func (SealingKey) GoString() string { return "SealingKey{REDACTED}" }

type SealingKeyProvider interface {
	Active(context.Context) (SealingKey, error)
	Open(context.Context, string) (SealingKey, error)
}

type AEADSealer struct {
	keys   SealingKeyProvider
	random io.Reader
}

func NewAEADSealer(keys SealingKeyProvider, random io.Reader) (*AEADSealer, error) {
	if keys == nil || random == nil {
		return nil, ErrInvalidArgument
	}
	return &AEADSealer{keys: keys, random: random}, nil
}

func NewProductionAEADSealer(keys SealingKeyProvider) (*AEADSealer, error) {
	return NewAEADSealer(keys, rand.Reader)
}

func (sealer *AEADSealer) Seal(ctx context.Context, identity Identity, state CapabilityState) (string, error) {
	key, err := sealer.keys.Active(ctx)
	if err != nil || !validIdentifier(key.id) {
		return "", ErrUnavailable
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(sealer.random, nonce); err != nil {
		return "", ErrUnavailable
	}
	plaintext, err := encodeState(state)
	if err != nil {
		return "", ErrInvariant
	}
	aad := capabilityAAD(identity, key.id)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	clear(plaintext)
	return "v1." + key.id + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (sealer *AEADSealer) Open(ctx context.Context, identity Identity, capability string) (CapabilityState, error) {
	parts := strings.Split(capability, ".")
	if len(parts) != 4 || parts[0] != "v1" || !validIdentifier(parts[1]) {
		return CapabilityState{}, ErrConflict
	}
	key, err := sealer.keys.Open(ctx, parts[1])
	if err != nil || key.id != parts[1] {
		return CapabilityState{}, ErrUnavailable
	}
	aead, err := newAEAD(key)
	if err != nil {
		return CapabilityState{}, ErrUnavailable
	}
	nonce, nonceErr := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	ciphertext, cipherErr := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if nonceErr != nil || cipherErr != nil || len(nonce) != aead.NonceSize() || len(ciphertext) != capabilityPlaintextBytes+aead.Overhead() {
		return CapabilityState{}, ErrConflict
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, capabilityAAD(identity, key.id))
	if err != nil {
		return CapabilityState{}, ErrConflict
	}
	defer clear(plaintext)
	return decodeState(plaintext)
}

func newAEAD(key SealingKey) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key.bytes[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func capabilityAAD(identity Identity, keyID string) []byte {
	return []byte("yukh:coordination-primitives:capability:v1\n" + keyID + "\n" + identity.tenant + "\n" + identity.principal)
}

func encodeState(state CapabilityState) ([]byte, error) {
	validated, err := NewCapabilityState(state.key, state.holder, state.expiresAt, state.epoch, state.fencingToken, state.tokenID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, capabilityPlaintextBytes)
	copy(out[0:64], validated.key)
	copy(out[64:128], validated.holder)
	binary.BigEndian.PutUint64(out[128:136], uint64(validated.expiresAt.UnixMilli()))
	binary.BigEndian.PutUint64(out[136:144], validated.epoch)
	binary.BigEndian.PutUint64(out[144:152], validated.fencingToken)
	copy(out[152:168], validated.tokenID[:])
	return out, nil
}

func decodeState(raw []byte) (CapabilityState, error) {
	if len(raw) != capabilityPlaintextBytes {
		return CapabilityState{}, ErrConflict
	}
	expiresMillis := binary.BigEndian.Uint64(raw[128:136])
	if expiresMillis > uint64(maxSafeInteger) {
		return CapabilityState{}, ErrConflict
	}
	var tokenID [16]byte
	copy(tokenID[:], raw[152:168])
	state, err := NewCapabilityState(coordination.Digest(raw[0:64]), coordination.Digest(raw[64:128]), time.UnixMilli(int64(expiresMillis)).UTC(), binary.BigEndian.Uint64(raw[136:144]), binary.BigEndian.Uint64(raw[144:152]), tokenID)
	if err != nil {
		return CapabilityState{}, ErrConflict
	}
	return state, nil
}
