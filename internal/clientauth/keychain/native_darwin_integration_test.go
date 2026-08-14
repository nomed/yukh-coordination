//go:build darwin && cgo

package keychain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const nativeQualificationEnvironment = "YUKH_RUN_NATIVE_KEYCHAIN_QUALIFICATION"

// TestNativeKeychainQualification is opt-in because it creates and deletes an
// explicit disposable Keychain file. It never selects or queries a default,
// Login, or Data Protection Keychain.
func TestNativeKeychainQualification(t *testing.T) {
	if os.Getenv(nativeQualificationEnvironment) != "1" {
		t.Skipf("set %s=1 to run the disposable native Keychain qualification", nativeQualificationEnvironment)
	}
	security, err := exec.LookPath("security")
	if err != nil {
		t.Skip("macOS security CLI is unavailable")
	}
	directory, err := os.MkdirTemp("", ".native-keychain-qualification-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	// macOS commonly returns /var/folders/... while /var is a symlink to
	// /private/var. Resolve the test-owned directory before exercising the
	// production boundary, which intentionally rejects paths containing symlinks.
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	profile := randomHex(t, 16)
	password := randomHex(t, 32)
	path := filepath.Join(directory, "qualification-"+randomHex(t, 16)+".keychain-db")
	keychainCreated := false
	itemCreated := false
	t.Cleanup(func() {
		if itemCreated {
			if err := exec.Command(security, "delete-generic-password", "-s", RootItemService, "-a", profile, path).Run(); err != nil {
				t.Errorf("delete disposable Keychain item: %v", err)
			}
		}
		if keychainCreated {
			if err := exec.Command(security, "delete-keychain", path).Run(); err != nil {
				t.Errorf("delete disposable Keychain: %v", err)
			}
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove disposable Keychain directory: %v", err)
		}
	})
	if err := exec.Command(security, "create-keychain", "-p", password, path).Run(); err != nil {
		t.Fatalf("create disposable Keychain: %v", err)
	}
	keychainCreated = true
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(security, "unlock-keychain", "-p", password, path).Run(); err != nil {
		t.Fatalf("unlock disposable Keychain: %v", err)
	}
	binding, err := NewBinding(profile, RootItemService, profile, "", path)
	if err != nil {
		t.Fatalf("bind disposable Keychain: %v", err)
	}
	first, err := NewSource(binding, CreationAllowed)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	firstKey, err := first.RootKey(ctx, profile)
	cancel()
	if err != nil || firstKey == ([32]byte{}) {
		t.Fatalf("create root item in disposable Keychain: %v", err)
	}
	itemCreated = true
	reopened, err := NewSource(binding, CreationProhibited)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	secondKey, err := reopened.RootKey(ctx, profile)
	cancel()
	if err != nil || secondKey != firstKey {
		t.Fatalf("reopen root item in disposable Keychain: %v", err)
	}
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(value)
}
