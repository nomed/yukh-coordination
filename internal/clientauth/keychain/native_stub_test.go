//go:build !darwin || !cgo

package keychain

import "testing"

func TestNonDarwinNativeSourceFailsClosed(t *testing.T) {
	binding := testBinding(t, "0123456789abcdef0123456789abcdef")
	source, err := NewSource(binding, CreationAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.RootKey(deadline(t), binding.Profile()); err == nil {
		t.Fatal("non-darwin source did not fail closed")
	}
}
