package keychain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSourceCreatesAndReopensOneExactRootKey(t *testing.T) {
	firstBinding := testBinding(t, "0123456789abcdef0123456789abcdef")
	secondBinding := testBinding(t, "fedcba9876543210fedcba9876543210")
	provider := newFakeProvider()
	first := testSource(firstBinding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	second := testSource(secondBinding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))

	key, err := first.RootKey(deadline(t), firstBinding.Profile())
	if err != nil || key == ([32]byte{}) {
		t.Fatalf("create first root: key=%x err=%v", key, err)
	}
	again, err := first.RootKey(deadline(t), firstBinding.Profile())
	if err != nil || again != key {
		t.Fatalf("reopen first root: key=%x err=%v", again, err)
	}
	other, err := second.RootKey(deadline(t), secondBinding.Profile())
	if err != nil || other == key {
		t.Fatalf("create isolated root: key=%x err=%v", other, err)
	}
	if provider.creates != 2 {
		t.Fatalf("creates=%d", provider.creates)
	}
}

func TestSourceFailsClosedForInvalidAndAmbiguousItems(t *testing.T) {
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	tests := []struct {
		name  string
		items []item
	}{
		{"multiple", []item{validFakeItem(binding, 1), validFakeItem(binding, 2)}},
		{"wrong-service", []item{{service: "other", account: binding.account, accessGroup: binding.accessGroup, accessibility: rootItemAccessibility, label: rootItemLabel, secret: bytes.Repeat([]byte{1}, 32)}}},
		{"wrong-account", []item{{service: binding.service, account: "other", accessGroup: binding.accessGroup, accessibility: rootItemAccessibility, label: rootItemLabel, secret: bytes.Repeat([]byte{1}, 32)}}},
		{"wrong-access-group", []item{{service: binding.service, account: binding.account, accessGroup: "ABCDE12345.com.example.other", accessibility: rootItemAccessibility, label: rootItemLabel, secret: bytes.Repeat([]byte{1}, 32)}}},
		{"wrong-accessibility", []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup, accessibility: "always", label: rootItemLabel, secret: bytes.Repeat([]byte{1}, 32)}}},
		{"wrong-label", []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup, accessibility: rootItemAccessibility, label: "other", secret: bytes.Repeat([]byte{1}, 32)}}},
		{"short-secret", []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup, accessibility: rootItemAccessibility, label: rootItemLabel, secret: bytes.Repeat([]byte{1}, 31)}}},
		{"zero-secret", []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup, accessibility: rootItemAccessibility, label: rootItemLabel, secret: make([]byte, 32)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := newFakeProvider()
			provider.items[binding.account] = test.items
			source := testSource(binding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
			key, err := source.RootKey(deadline(t), binding.Profile())
			if err == nil || key != ([32]byte{}) || provider.creates != 0 {
				t.Fatalf("accepted invalid item: key=%x err=%v creates=%d", key, err, provider.creates)
			}
		})
	}
}

func TestSourceFailsClosedForProviderStatusFailures(t *testing.T) {
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	for _, status := range []string{"locked", "authorization", "interaction", "ui-prompt", "provider"} {
		t.Run(status, func(t *testing.T) {
			provider := newFakeProvider()
			provider.lookupErr = errors.New(status)
			source := testSource(binding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
			if _, err := source.RootKey(deadline(t), binding.Profile()); err == nil || provider.creates != 0 {
				t.Fatalf("accepted status=%q err=%v creates=%d", status, err, provider.creates)
			}
		})
	}
}

func TestSourceCreationPolicyAndAmbiguousCreateReconcileOnce(t *testing.T) {
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	provider := newFakeProvider()
	denied := testSource(binding, CreationProhibited, provider, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if _, err := denied.RootKey(deadline(t), binding.Profile()); err == nil || provider.creates != 0 {
		t.Fatalf("prohibited source created root: err=%v creates=%d", err, provider.creates)
	}

	provider = newFakeProvider()
	provider.ambiguousCreate = true
	provider.persistBeforeError = true
	source := testSource(binding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{4}, 32)))
	key, err := source.RootKey(deadline(t), binding.Profile())
	if err != nil || key == ([32]byte{}) || provider.creates != 1 || provider.lookups != 2 {
		t.Fatalf("ambiguous reconcile: key=%x err=%v creates=%d lookups=%d", key, err, provider.creates, provider.lookups)
	}

	provider = newFakeProvider()
	provider.createErr = errors.New("provider failure")
	source = testSource(binding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
	if _, err := source.RootKey(deadline(t), binding.Profile()); err == nil || provider.creates != 1 || provider.lookups != 1 {
		t.Fatalf("definitive failure retried: err=%v creates=%d lookups=%d", err, provider.creates, provider.lookups)
	}
}

func TestSourceRejectsWrongProfileAndUnboundedContext(t *testing.T) {
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	provider := newFakeProvider()
	source := testSource(binding, CreationAllowed, provider, bytes.NewReader(bytes.Repeat([]byte{6}, 32)))
	if _, err := source.RootKey(context.Background(), binding.Profile()); err == nil {
		t.Fatal("accepted unbounded context")
	}
	if _, err := source.RootKey(deadline(t), "fedcba9876543210fedcba9876543210"); err == nil || provider.lookups != 0 {
		t.Fatalf("wrong profile reached provider: err=%v lookups=%d", err, provider.lookups)
	}
}

func TestBindingIsClosedAndRedacted(t *testing.T) {
	for _, test := range []struct {
		name                             string
		profile, service, account, group string
	}{
		{"wrong-service", "0123456789abcdef0123456789abcdef", "other", "0123456789abcdef0123456789abcdef", ""},
		{"cross-wired-account", "0123456789abcdef0123456789abcdef", RootItemService, "fedcba9876543210fedcba9876543210", ""},
		{"invalid-profile", "not-opaque", RootItemService, "not-opaque", ""},
		{"invalid-access-group", "0123456789abcdef0123456789abcdef", RootItemService, "0123456789abcdef0123456789abcdef", "group/other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if binding, err := NewBinding(test.profile, test.service, test.account, test.group, testKeychainFile(t)); err == nil || binding != (Binding{}) {
				t.Fatalf("accepted binding=%#v err=%v", binding, err)
			}
		})
	}
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	if binding.String() != "Binding{REDACTED}" || binding.GoString() != "Binding{REDACTED}" {
		t.Fatal("binding formatting leaked")
	}
	if binding, err := NewBinding("fedcba9876543210fedcba9876543210", RootItemService, "fedcba9876543210fedcba9876543210", "ABCDE12345.com.example.yukh", testKeychainFile(t)); err == nil || binding != (Binding{}) {
		t.Fatalf("accepted Data Protection Keychain access group: binding=%#v err=%v", binding, err)
	}
}

func testBinding(t *testing.T, profile string) Binding {
	t.Helper()
	binding, err := NewBinding(profile, RootItemService, profile, "", testKeychainFile(t))
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestBindingRejectsUnsafeKeychainPaths(t *testing.T) {
	directory, err := os.MkdirTemp(".", ".keychain-path-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(absolute, "public.keychain-db")
	if err := os.WriteFile(public, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(absolute, "target.keychain-db")
	if err := os.WriteFile(target, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(absolute, "link.keychain-db")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(absolute, "link-directory")
	if err := os.Symlink(absolute, linkDirectory); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"relative.keychain-db",
		filepath.Join(absolute, "missing.keychain-db"),
		public,
		symlink,
		filepath.Join(linkDirectory, "target.keychain-db"),
	} {
		if binding, err := NewBinding("0123456789abcdef0123456789abcdef", RootItemService, "0123456789abcdef0123456789abcdef", "", path); err == nil || binding != (Binding{}) {
			t.Fatalf("accepted unsafe keychain path %q: binding=%#v err=%v", path, binding, err)
		}
	}
}

func testKeychainFile(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(".", ".keychain-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs(filepath.Join(directory, "root.keychain-db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSource(binding Binding, creation CreationPolicy, provider provider, entropy *bytes.Reader) *Source {
	return &Source{binding: binding, creation: creation, provider: provider, entropy: entropy}
}

func deadline(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

type fakeProvider struct {
	items              map[string][]item
	lookups            int
	creates            int
	lookupErr          error
	createErr          error
	ambiguousCreate    bool
	persistBeforeError bool
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{items: make(map[string][]item)}
}

func (p *fakeProvider) Lookup(_ context.Context, binding Binding) ([]item, error) {
	p.lookups++
	if p.lookupErr != nil {
		return nil, p.lookupErr
	}
	values := p.items[binding.account]
	result := make([]item, len(values))
	for index := range values {
		result[index] = values[index]
		result[index].secret = append([]byte(nil), values[index].secret...)
	}
	return result, nil
}

func (p *fakeProvider) Create(_ context.Context, binding Binding, key []byte) (bool, error) {
	p.creates++
	if p.persistBeforeError {
		p.items[binding.account] = []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup,
			accessibility: rootItemAccessibility, label: rootItemLabel, secret: append([]byte(nil), key...)}}
	}
	if p.createErr != nil {
		return p.ambiguousCreate, p.createErr
	}
	if p.ambiguousCreate {
		return true, errors.New("ambiguous create")
	}
	p.items[binding.account] = []item{{service: binding.service, account: binding.account, accessGroup: binding.accessGroup,
		accessibility: rootItemAccessibility, label: rootItemLabel, secret: append([]byte(nil), key...)}}
	return false, nil
}

func validFakeItem(binding Binding, byteValue byte) item {
	return item{service: binding.service, account: binding.account, accessGroup: binding.accessGroup,
		accessibility: rootItemAccessibility, label: rootItemLabel, secret: bytes.Repeat([]byte{byteValue}, 32)}
}
