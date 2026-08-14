package secretservice

import (
	"bytes"
	"math/big"
	"testing"
)

func TestDeriveSessionKeyUsesSecretServiceHKDF(t *testing.T) {
	key, err := deriveSessionKey(big.NewInt(1), []byte{2})
	if err != nil {
		t.Fatalf("derive session key: %v", err)
	}
	want := []byte{
		0xe4, 0x3c, 0xd1, 0xfa, 0xe5, 0x5c, 0xf9, 0x44,
		0x82, 0x83, 0x36, 0xe2, 0x77, 0x73, 0x8f, 0x68,
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("derived session key = %x, want %x", key, want)
	}
}
