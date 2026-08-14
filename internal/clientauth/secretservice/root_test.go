package secretservice

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
	"golang.org/x/sys/unix"
)

func TestRootKeyCreatesOneExactKeyPerProfile(t *testing.T) {
	service := newFakeService()
	entropy := append(bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)...)
	handle := testHandle(t, service, bytes.NewReader(entropy))
	first, err := handle.RootKey(deadlineContext(t), "profile-a")
	if err != nil {
		t.Fatalf("create profile-a root: %v", err)
	}
	again, err := handle.RootKey(deadlineContext(t), "profile-a")
	if err != nil || first != again {
		t.Fatalf("reopened root key: key=%x err=%v", again, err)
	}
	second, err := handle.RootKey(deadlineContext(t), "profile-b")
	if err != nil || first == second {
		t.Fatalf("profile separation failed: key=%x err=%v", second, err)
	}
	if service.createCalls != 2 || service.promptCalls != 0 || service.closeCalls != service.openCalls {
		t.Fatalf("unexpected provider calls: creates=%d prompts=%d opens=%d closes=%d", service.createCalls, service.promptCalls, service.openCalls, service.closeCalls)
	}
	for _, item := range service.items {
		if item.contentType != rootContentType || item.label != rootLabel || len(item.attributes) != 3 ||
			item.attributes[contentSchemaAttribute] != rootContentType ||
			item.attributes[rootSchemaAttribute] != workstation.RootItemSchema || item.attributes[rootProfileAttribute] == "" {
			t.Fatalf("created wrong root-item shape: %#v", item)
		}
	}
}

func TestRootKeyFailsClosedForLockedPromptMultipleAndMalformedItems(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(*fakeService)
	}{
		{"locked-collection", func(service *fakeService) { service.locked = true }},
		{"locked-item", func(service *fakeService) {
			service.put(rootItem{path: "/org/freedesktop/secrets/collection/yukh/locked", attributes: rootAttrs("profile-a"), contentType: rootContentType, label: rootLabel, value: [32]byte{1}})
			service.itemLocked = true
		}},
		{"prompt", func(service *fakeService) { service.promptCreate = true }},
		{"multiple", func(service *fakeService) {
			service.put(rootItem{path: "/org/freedesktop/secrets/collection/yukh/one", attributes: rootAttrs("profile-a"), contentType: rootContentType, label: rootLabel, value: [32]byte{1}})
			service.put(rootItem{path: "/org/freedesktop/secrets/collection/yukh/two", attributes: rootAttrs("profile-a"), contentType: rootContentType, label: rootLabel, value: [32]byte{2}})
		}},
		{"malformed", func(service *fakeService) {
			service.put(rootItem{path: "/org/freedesktop/secrets/collection/yukh/bad", attributes: rootAttrs("profile-a"), contentType: "text/plain", label: rootLabel, value: [32]byte{1}})
		}},
		{"wrong-secret-length", func(service *fakeService) {
			service.put(rootItem{path: "/org/freedesktop/secrets/collection/yukh/short", attributes: rootAttrs("profile-a"), contentType: rootContentType, label: rootLabel, value: [32]byte{1}})
			service.shortSecret = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newFakeService()
			test.arrange(service)
			handle := testHandle(t, service, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
			key, err := handle.RootKey(deadlineContext(t), "profile-a")
			if err == nil || key != ([32]byte{}) {
				t.Fatalf("accepted unsafe root state: key=%x err=%v", key, err)
			}
			if test.name != "prompt" && service.promptCalls != 0 {
				t.Fatalf("adapter invoked prompt: %d", service.promptCalls)
			}
		})
	}
}

func TestRootKeyReconcilesOnlyAmbiguousCreateOnce(t *testing.T) {
	service := newFakeService()
	service.createError = errors.New("transport interrupted")
	service.createAmbiguous = true
	service.createBeforeError = true
	handle := testHandle(t, service, bytes.NewReader(bytes.Repeat([]byte{4}, 32)))
	key, err := handle.RootKey(deadlineContext(t), "profile-a")
	if err != nil || key == ([32]byte{}) {
		t.Fatalf("ambiguous create did not reconcile: key=%x err=%v", key, err)
	}
	if service.createCalls != 1 || service.openCalls != 3 || service.closeCalls != 3 {
		t.Fatalf("create was retried or session leaked: creates=%d opens=%d closes=%d", service.createCalls, service.openCalls, service.closeCalls)
	}

	service = newFakeService()
	service.createError = errors.New("definitive provider failure")
	handle = testHandle(t, service, bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
	if _, err := handle.RootKey(deadlineContext(t), "profile-a"); err == nil {
		t.Fatal("definitive create failure succeeded")
	}
	if service.createCalls != 1 || service.openCalls != 2 || service.closeCalls != 2 {
		t.Fatalf("definitive create retried: creates=%d opens=%d closes=%d", service.createCalls, service.openCalls, service.closeCalls)
	}
}

func TestFactoryRejectsInvalidBindingWithoutAmbientBusDiscovery(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/ambient")
	called := false
	factory := &Factory{
		open: func(context.Context, workstation.SecretServiceBinding, *os.File) (rootService, error) {
			called = true
			return newFakeService(), nil
		},
		entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 32)),
	}
	descriptor, err := os.CreateTemp(".", ".secretservice-descriptor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = descriptor.Close()
		_ = os.Remove(descriptor.Name())
	})
	if handle, err := factory.OpenRootKey(deadlineContext(t), workstation.SecretServiceBinding{}, descriptor); err == nil || handle != nil {
		t.Fatalf("invalid binding opened adapter: handle=%v err=%v", handle, err)
	}
	if called {
		t.Fatal("invalid binding attempted ambient or supplied bus access")
	}
}

func TestProductionFactoryUsesOnlyProvidedDBusStream(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/ambient-must-not-be-opened")
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	client := os.NewFile(uintptr(pair[0]), "caller-dbus")
	server := os.NewFile(uintptr(pair[1]), "fake-dbus")
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	handshake := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(server)
		first, err := reader.ReadByte()
		if err != nil || first != 0 {
			handshake <- errors.New("missing D-Bus initial byte")
			return
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "AUTH\r\n" {
			handshake <- errors.New("missing D-Bus auth request")
			return
		}
		if _, err := server.Write([]byte("REJECTED EXTERNAL\r\n")); err != nil {
			handshake <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || line != "AUTH EXTERNAL\r\n" {
			handshake <- errors.New("missing explicit EXTERNAL authentication")
			return
		}
		if _, err := server.Write([]byte("DATA\r\n")); err != nil {
			handshake <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || line != "DATA\r\n" {
			handshake <- errors.New("unexpected EXTERNAL challenge response")
			return
		}
		if _, err := server.Write([]byte("OK 0123456789abcdef0123456789abcdef\r\n")); err != nil {
			handshake <- err
			return
		}
		line, err = reader.ReadString('\n')
		if err != nil || line != "BEGIN\r\n" {
			handshake <- errors.New("missing D-Bus begin")
			return
		}
		if _, err := reader.ReadByte(); err != nil {
			handshake <- err
			return
		}
		handshake <- nil
	}()
	config := testConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	handle, err := NewRootKeyFactory().OpenRootKey(ctx, config.SecretServiceBinding(), client)
	if err == nil || handle != nil {
		t.Fatalf("fake peer unexpectedly opened root key: handle=%v err=%v", handle, err)
	}
	if _, err := client.Stat(); err != nil {
		t.Fatalf("factory closed its caller-owned descriptor on error: %v", err)
	}
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatalf("factory did not use caller stream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("factory did not contact caller-provided D-Bus stream")
	}
}

func testHandle(t *testing.T, service *fakeService, entropy io.Reader) *handle {
	t.Helper()
	config := testConfig(t)
	return &handle{service: service, binding: config.SecretServiceBinding(), entropy: entropy}
}

func testConfig(t *testing.T) *workstation.Config {
	t.Helper()
	config, err := workstation.ParseConfig([]byte(`{"profile":"linux-secret-service-v1","local_custody_database_path":"/private/custody.db","relay_base_uri":"https://relay.example","secret_service_name":"org.freedesktop.secrets","secret_service_collection_path":"/org/freedesktop/secrets/collection/yukh","secret_service_root_item_schema":"yukh-coordination/linux-secret-service-root/v1","connection_deadline_ms":100,"request_deadline_ms":200,"operation_deadline_ms":300}`))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func deadlineContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

func rootAttrs(profile string) map[string]string {
	return map[string]string{
		rootSchemaAttribute:  workstation.RootItemSchema,
		rootProfileAttribute: profile,
	}
}

type fakeService struct {
	items             map[string]rootItem
	locked            bool
	itemLocked        bool
	shortSecret       bool
	promptCreate      bool
	createError       error
	createAmbiguous   bool
	createBeforeError bool
	openCalls         int
	closeCalls        int
	createCalls       int
	promptCalls       int
}

func newFakeService() *fakeService {
	return &fakeService{items: make(map[string]rootItem)}
}

func (s *fakeService) Close() error { return nil }

func (s *fakeService) OpenSession(context.Context) (rootSession, error) {
	s.openCalls++
	return &fakeSession{service: s}, nil
}

func (s *fakeService) CollectionItems(context.Context) (bool, []string, error) {
	paths := make([]string, 0, len(s.items))
	for path := range s.items {
		paths = append(paths, path)
	}
	return s.locked, paths, nil
}

func (s *fakeService) ItemMetadata(_ context.Context, path string) (itemMetadata, error) {
	item, exists := s.items[path]
	if !exists {
		return itemMetadata{}, errors.New("missing item")
	}
	return itemMetadata{
		path: path, locked: s.itemLocked, attributes: copyAttributes(item.attributes),
		contentType: item.contentType, label: item.label,
	}, nil
}

func (s *fakeService) ItemSecret(_ context.Context, _ rootSession, path string) ([]byte, string, error) {
	item, exists := s.items[path]
	if !exists {
		return nil, "", errors.New("missing item")
	}
	if s.shortSecret {
		return append([]byte(nil), item.value[:31]...), item.contentType, nil
	}
	return append([]byte(nil), item.value[:]...), item.contentType, nil
}

func (s *fakeService) CreateItem(_ context.Context, _ rootSession, item rootItem) (string, bool, bool, error) {
	s.createCalls++
	path := "/org/freedesktop/secrets/collection/yukh/root_" + string(rune('a'+s.createCalls))
	item.path = path
	if s.createBeforeError {
		s.put(item)
	}
	if s.createError != nil {
		return "", false, s.createAmbiguous, s.createError
	}
	if s.promptCreate {
		return path, true, false, nil
	}
	s.put(item)
	return path, false, false, nil
}

func (s *fakeService) put(item rootItem) {
	item.attributes = copyAttributes(item.attributes)
	s.items[item.path] = item
}

type fakeSession struct {
	service *fakeService
	closed  bool
}

func (s *fakeSession) Close(context.Context) error {
	if !s.closed {
		s.closed = true
		s.service.closeCalls++
	}
	return nil
}

func copyAttributes(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source))
	for key, value := range source {
		copy[key] = value
	}
	return copy
}
