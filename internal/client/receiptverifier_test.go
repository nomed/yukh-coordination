package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func TestEd25519ReceiptVerifier(t *testing.T) {
	preimage, err := os.ReadFile("../../conformance/canonical/receipt-signature-preimage.canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(preimage, &receipt); err != nil {
		t.Fatal(err)
	}
	signature, _ := hex.DecodeString("5a239004a0a226766d0c246a1c386b8295928d677170ec458456a3fe43918e0286467d2970c7c5511399fe373bf2cd0fde00749c81b27732ecae277cc05ed001")
	receipt["signature"] = base64.RawURLEncoding.EncodeToString(signature)
	raw, _ := json.Marshal(receipt)
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	verifier, err := NewEd25519ReceiptVerifier(map[string]ed25519.PublicKey{"key-1": public})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(raw); err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] ^= 1
	if err := verifier.Verify(raw); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("changed receipt error=%v", err)
	}
}

func TestEd25519ReceiptVerifierRejectsUnknownKey(t *testing.T) {
	public := make(ed25519.PublicKey, ed25519.PublicKeySize)
	verifier, err := NewEd25519ReceiptVerifier(map[string]ed25519.PublicKey{"other": public})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify([]byte(`{}`)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("error=%v", err)
	}
}
