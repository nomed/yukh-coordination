package localcustody

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDescriptorRootKeySource(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	key := [32]byte{1, 2, 3, 4}
	if _, err := write.Write(key[:]); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	source, err := NewDescriptorRootKeySource(int(read.Fd()), "default")
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.RootKey(context.Background(), "default")
	if err != nil || got != key {
		t.Fatalf("key=%x err=%v", got, err)
	}
	if _, err := source.RootKey(context.Background(), "other"); !errors.Is(err, ErrRootKeyUnavailable) {
		t.Fatalf("wrong-profile error=%v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.RootKey(context.Background(), "default"); !errors.Is(err, ErrRootKeyUnavailable) {
		t.Fatalf("closed error=%v", err)
	}
}

func TestDescriptorRootKeySourceRejectsInvalidInputs(t *testing.T) {
	if _, err := NewDescriptorRootKeySource(2, "default"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("descriptor error=%v", err)
	}
	read, write, _ := os.Pipe()
	_, _ = write.Write(make([]byte, 31))
	_ = write.Close()
	if _, err := NewDescriptorRootKeySource(int(read.Fd()), "default"); !errors.Is(err, ErrRootKeyUnavailable) {
		t.Fatalf("short key error=%v", err)
	}
}
