package primitivesstaging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitives"
	"golang.org/x/sys/unix"
)

type keyLifecycleFixture struct {
	events []bool
	err    error
}

func (fixture *keyLifecycleFixture) RecordCapabilityKeyLifecycle(_ context.Context, loaded bool) error {
	fixture.events = append(fixture.events, loaded)
	return fixture.err
}

func TestCapabilityKeyringDescriptorRotationAndZeroization(t *testing.T) {
	now := time.Date(2026, 8, 3, 19, 0, 0, 0, time.UTC)
	maxLease := 2 * time.Minute
	oldMaterial := bytes.Repeat([]byte{1}, 32)
	newMaterial := bytes.Repeat([]byte{2}, 32)
	oldOnly := canonicalKeyring(t, []capabilityKeyJSON{keyJSON("old-key", oldMaterial, now.Add(-2*time.Minute), now.Add(-time.Minute), now.Add(time.Minute))})
	oldRing, err := parseCapabilityKeyring(oldOnly, maxLease, func() time.Time { return now.Add(-90 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := primitives.NewAEADSealer(oldRing, bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	identity, _ := primitives.NewIdentity("tenant-a", "principal-a")
	state, _ := primitives.NewCapabilityState(coordination.Digest(strings.Repeat("a", 64)), coordination.Digest(strings.Repeat("b", 64)), now.Add(30*time.Second), 1, 1, [16]byte{1})
	oldCapability, err := sealer.Seal(context.Background(), identity, state)
	if err != nil || !strings.HasPrefix(oldCapability, "v1.old-key.") {
		t.Fatalf("old capability = %q, %v", oldCapability, err)
	}
	oldRing.zeroLocked()

	raw := canonicalKeyring(t, []capabilityKeyJSON{
		keyJSON("old-key", oldMaterial, now.Add(-2*time.Minute), now.Add(-time.Minute), now.Add(time.Minute)),
		keyJSON("active-key", newMaterial, now.Add(-time.Minute), now.Add(time.Minute), now.Add(3*time.Minute)),
	})
	descriptors, descriptor := descriptorFixture(t, raw)
	audit := &keyLifecycleFixture{}
	keyring, err := OpenCapabilityKeyring(context.Background(), descriptors, maxLease, func() time.Time { return now }, audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Read(descriptor, make([]byte, 1)); err == nil {
		t.Fatal("capability descriptor remained open")
	}
	activeSealer, _ := primitives.NewAEADSealer(keyring, bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	capability, err := activeSealer.Seal(context.Background(), identity, state)
	if err != nil || !strings.HasPrefix(capability, "v1.active-key.") {
		t.Fatalf("active capability = %q, %v", capability, err)
	}
	if _, err := activeSealer.Open(context.Background(), identity, oldCapability); err != nil {
		t.Fatalf("old capability did not survive bounded rotation: %v", err)
	}
	held := append([]byte(nil), keyring.keys[keyring.active].material...)
	if bytes.Equal(held, make([]byte, 32)) {
		t.Fatal("fixture key unexpectedly zero")
	}
	backing := keyring.keys[keyring.active].material
	if err := keyring.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if keyring.Ready() || !bytes.Equal(backing, make([]byte, 32)) {
		t.Fatal("keyring remained ready or retained material")
	}
	if len(audit.events) != 2 || !audit.events[0] || audit.events[1] {
		t.Fatalf("lifecycle events = %v", audit.events)
	}
	if _, err := OpenCapabilityKeyring(context.Background(), descriptors, maxLease, func() time.Time { return now }, audit); !errors.Is(err, ErrInvalid) {
		t.Fatalf("descriptor reuse error = %v", err)
	}
}

func TestCapabilityKeyringRejectsAmbiguousAndOverRetainedMaterial(t *testing.T) {
	now := time.Date(2026, 8, 3, 19, 0, 0, 0, time.UTC)
	maxLease := 2 * time.Minute
	tests := []struct {
		name string
		keys []capabilityKeyJSON
	}{
		{"two-active", []capabilityKeyJSON{
			keyJSON("a", bytes.Repeat([]byte{1}, 32), now.Add(-time.Minute), now.Add(time.Minute), now.Add(3*time.Minute)),
			keyJSON("b", bytes.Repeat([]byte{2}, 32), now.Add(-30*time.Second), now.Add(90*time.Second), now.Add(210*time.Second)),
		}},
		{"future", []capabilityKeyJSON{keyJSON("a", bytes.Repeat([]byte{1}, 32), now.Add(time.Second), now.Add(time.Minute), now.Add(3*time.Minute))}},
		{"over-retained", []capabilityKeyJSON{keyJSON("a", bytes.Repeat([]byte{1}, 32), now.Add(-time.Minute), now.Add(time.Minute), now.Add(4*time.Minute))}},
		{"expired", []capabilityKeyJSON{keyJSON("a", bytes.Repeat([]byte{1}, 32), now.Add(-4*time.Minute), now.Add(-3*time.Minute), now.Add(-time.Minute))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if keyring, err := parseCapabilityKeyring(canonicalKeyring(t, test.keys), maxLease, func() time.Time { return now }); !errors.Is(err, ErrInvalid) || keyring != nil {
				t.Fatalf("keyring=%v error=%v", keyring, err)
			}
		})
	}
}

func TestCapabilityKeyringRedactsAndBoundsDescriptor(t *testing.T) {
	now := time.Date(2026, 8, 3, 19, 0, 0, 0, time.UTC)
	secret := bytes.Repeat([]byte{7}, 32)
	raw := canonicalKeyring(t, []capabilityKeyJSON{keyJSON("active-key", secret, now.Add(-time.Minute), now.Add(time.Minute), now.Add(2*time.Minute))})
	descriptors, _ := descriptorFixture(t, raw)
	keyring, err := OpenCapabilityKeyring(context.Background(), descriptors, time.Minute, func() time.Time { return now }, &keyLifecycleFixture{})
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close(context.Background())
	if strings.Contains(keyring.String(), base64.RawURLEncoding.EncodeToString(secret)) {
		t.Fatal("string exposed key")
	}
	if _, err := json.Marshal(keyring); !errors.Is(err, ErrInvalid) {
		t.Fatalf("marshal error = %v", err)
	}
	oversized := bytes.Repeat([]byte("x"), maxCapabilityKeyringBytes+1)
	descriptors, _ = descriptorFixture(t, oversized)
	if _, err := OpenCapabilityKeyring(context.Background(), descriptors, time.Minute, func() time.Time { return now }, &keyLifecycleFixture{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized descriptor error = %v", err)
	}
	descriptors, _ = descriptorFixture(t, raw[:len(raw)-1])
	if _, err := OpenCapabilityKeyring(context.Background(), descriptors, time.Minute, func() time.Time { return now }, &keyLifecycleFixture{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("truncated descriptor error = %v", err)
	}
	descriptors, _ = descriptorFixture(t, raw)
	if _, err := OpenCapabilityKeyring(context.Background(), descriptors, time.Minute, func() time.Time { return now }, &keyLifecycleFixture{err: ErrUnavailable}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lifecycle audit failure = %v", err)
	}
}

func keyJSON(id string, material []byte, from, until, decrypt time.Time) capabilityKeyJSON {
	encoded := base64.RawURLEncoding.EncodeToString(material)
	return capabilityKeyJSON{KeyID: id, Key: json.RawMessage(`"` + encoded + `"`), SealFrom: from.Format("2006-01-02T15:04:05.000Z"), SealUntil: until.Format("2006-01-02T15:04:05.000Z"), DecryptUntil: decrypt.Format("2006-01-02T15:04:05.000Z")}
}

func canonicalKeyring(t *testing.T, keys []capabilityKeyJSON) []byte {
	t.Helper()
	raw, _ := json.Marshal(capabilityKeyringJSON{Profile: capabilityKeyringProfile, Keys: keys})
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func descriptorFixture(t *testing.T, raw []byte) (*SecretDescriptors, int) {
	t.Helper()
	descriptor, err := unix.MemfdCreate("capability-key-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	if written, err := unix.Write(descriptor, raw); err != nil || written != len(raw) {
		t.Fatal(err)
	}
	if _, err := unix.Seek(descriptor, 0, 0); err != nil {
		t.Fatal(err)
	}
	descriptors, err := NewSecretDescriptors(descriptor+1000, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return descriptors, descriptor
}
