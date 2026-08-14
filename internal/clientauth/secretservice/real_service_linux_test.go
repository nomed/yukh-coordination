//go:build linux

package secretservice

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/nomed/yukh-coordination/internal/clientauth/workstation"
	"golang.org/x/sys/unix"
)

const (
	qualificationProviderEnv   = "YUKH_SECRET_SERVICE_QUALIFICATION"
	qualificationSocketEnv     = "YUKH_SECRET_SERVICE_QUALIFICATION_BUS_SOCKET"
	qualificationCollectionEnv = "YUKH_SECRET_SERVICE_QUALIFICATION_COLLECTION"
	qualificationProfile       = "secret-service-qualification-profile-v1"
)

func TestRealSecretServiceQualification(t *testing.T) {
	provider := os.Getenv(qualificationProviderEnv)
	if provider == "" {
		t.Skip("set YUKH_SECRET_SERVICE_QUALIFICATION for an explicit real-service qualification")
	}
	if provider != "gnome-keyring" && provider != "keepassxc" {
		t.Fatalf("unsupported real-service qualification provider %q", provider)
	}
	socket := os.Getenv(qualificationSocketEnv)
	collection := os.Getenv(qualificationCollectionEnv)
	if socket == "" || collection == "" {
		t.Fatal("real-service qualification requires an explicit private D-Bus socket and collection")
	}
	binding := qualificationBinding(t, collection)

	// This deliberately points at the real private bus. A supplied unusable
	// stream must still fail rather than causing the adapter to open it.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+socket)

	t.Run("unlocked-create-and-reopen", func(t *testing.T) {
		first := qualificationRootKey(t, socket, binding)
		second := qualificationRootKey(t, socket, binding)
		if first != second {
			t.Fatal("real Secret Service did not persist the exact root key")
		}
	})

	t.Run("rejects-ambient-bus-fallback", func(t *testing.T) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		client := os.NewFile(uintptr(pair[0]), "qualification-unusable-dbus")
		server := os.NewFile(uintptr(pair[1]), "qualification-unusable-peer")
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		handle, err := NewRootKeyFactory().OpenRootKey(ctx, binding, client)
		if err == nil || handle != nil {
			if handle != nil {
				_ = handle.Close()
			}
			t.Fatal("adapter accepted an unusable supplied stream or opened the ambient bus")
		}
	})

	t.Run("locked-collection-never-prompts", func(t *testing.T) {
		prompt := qualificationLock(t, socket, binding.Collection())
		if prompt != "/" {
			t.Fatalf("service lock requires prompt %q; harness intentionally did not invoke it", prompt)
		}
		bus := qualificationBusFile(t, socket)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		handle, err := NewRootKeyFactory().OpenRootKey(ctx, binding, bus)
		if err != nil {
			_ = bus.Close()
			t.Fatalf("open adapter on supplied private bus: %v", err)
		}
		t.Cleanup(func() { _ = handle.Close() })
		if _, err := handle.RootKey(ctx, qualificationProfile); err == nil {
			t.Fatal("adapter read a locked collection")
		}
	})
}

func qualificationBinding(t *testing.T, collection string) workstation.SecretServiceBinding {
	t.Helper()
	configJSON := fmt.Sprintf(
		`{"profile":"linux-secret-service-v1","local_custody_database_path":"/private/custody.db","relay_base_uri":"https://relay.example","secret_service_name":"org.freedesktop.secrets","secret_service_collection_path":%q,"secret_service_root_item_schema":"yukh-coordination/linux-secret-service-root/v1","connection_deadline_ms":100,"request_deadline_ms":200,"operation_deadline_ms":300}`,
		collection,
	)
	config, err := workstation.ParseConfig([]byte(configJSON))
	if err != nil {
		t.Fatalf("parse explicit Secret Service binding: %v", err)
	}
	return config.SecretServiceBinding()
}

func qualificationRootKey(t *testing.T, socket string, binding workstation.SecretServiceBinding) [32]byte {
	t.Helper()
	bus := qualificationBusFile(t, socket)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handle, err := NewRootKeyFactory().OpenRootKey(ctx, binding, bus)
	if err != nil {
		_ = bus.Close()
		t.Fatalf("open adapter on supplied private bus: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	key, err := handle.RootKey(ctx, qualificationProfile)
	if err != nil {
		t.Fatalf("read root key from real Secret Service: %v", err)
	}
	return key
}

func qualificationBusFile(t *testing.T, socket string) *os.File {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		t.Fatalf("dial supplied private D-Bus socket: %v", err)
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		t.Fatal("supplied D-Bus socket did not create a Unix connection")
	}
	file, err := unixConnection.File()
	closeErr := connection.Close()
	if err != nil || closeErr != nil {
		if file != nil {
			_ = file.Close()
		}
		t.Fatalf("duplicate supplied private D-Bus connection: file=%v close=%v", err, closeErr)
	}
	return file
}

func qualificationLock(t *testing.T, socket, collection string) dbus.ObjectPath {
	t.Helper()
	connection := qualificationConnection(t, socket)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	call := connection.Object("org.freedesktop.secrets", secretServicePath).CallWithContext(
		ctx, serviceInterface+".Lock", dbus.FlagNoAutoStart, []dbus.ObjectPath{dbus.ObjectPath(collection)},
	)
	storeErr := call.Store(&locked, &prompt)
	if call.Err != nil || storeErr != nil {
		if call.Err != nil {
			t.Fatalf("lock configured real Secret Service collection: %v", call.Err)
		}
		t.Fatalf("decode configured real Secret Service lock response: %v", storeErr)
	}
	if !prompt.IsValid() {
		t.Fatal("real Secret Service returned an invalid lock prompt path")
	}
	return prompt
}

func qualificationConnection(t *testing.T, socket string) *dbus.Conn {
	t.Helper()
	bus := qualificationBusFile(t, socket)
	transport, err := net.FileConn(bus)
	closeErr := bus.Close()
	if err != nil || closeErr != nil {
		_ = bus.Close()
		t.Fatalf("open supplied private D-Bus transport: file=%v close=%v", err, closeErr)
	}
	if err := transport.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = transport.Close()
		t.Fatalf("bound supplied private D-Bus transport: %v", err)
	}
	connection, err := dbus.NewConn(transport)
	if err == nil {
		err = connection.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))})
	}
	if err == nil {
		err = connection.Hello()
	}
	_ = transport.SetDeadline(time.Time{})
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		} else {
			_ = transport.Close()
		}
		t.Fatalf("authenticate supplied private D-Bus transport: %v", err)
	}
	return connection
}
