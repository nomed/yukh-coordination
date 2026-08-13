package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

// Ed25519ReceiptVerifier verifies closed protocol receipts against an explicit
// immutable key set. Key discovery, network refresh, and private material are
// deliberately outside this adapter.
type Ed25519ReceiptVerifier struct {
	validator *protocol.Validator
	keys      map[string]ed25519.PublicKey
}

func NewEd25519ReceiptVerifier(keys map[string]ed25519.PublicKey) (*Ed25519ReceiptVerifier, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidInput
	}
	validator, err := protocol.NewValidator()
	if err != nil {
		return nil, ErrUnavailable
	}
	owned := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		if id == "" || len(id) > 128 || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalidInput
		}
		owned[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Ed25519ReceiptVerifier{validator: validator, keys: owned}, nil
}

func (v *Ed25519ReceiptVerifier) Verify(raw []byte) error {
	if v == nil || v.validator == nil || v.validator.ValidateReceipt(raw) != nil {
		return ErrInvalidRecord
	}
	var receipt map[string]any
	if json.Unmarshal(raw, &receipt) != nil {
		return ErrInvalidRecord
	}
	keyID, keyOK := receipt["key_id"].(string)
	algorithm, algorithmOK := receipt["signature_algorithm"].(string)
	signatureText, signatureOK := receipt["signature"].(string)
	key, trusted := v.keys[keyID]
	if !keyOK || !algorithmOK || algorithm != "ed25519" || !signatureOK || !trusted {
		return ErrInvalidRecord
	}
	delete(receipt, "signature")
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return ErrInvalidRecord
	}
	unsigned, err = jsoncanonicalizer.Transform(unsigned)
	if err != nil {
		return ErrInvalidRecord
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(signatureText)
	signingInput := make([]byte, 0, len("yukh-coordination-receipt-v0.1\x00")+len(unsigned))
	signingInput = append(signingInput, "yukh-coordination-receipt-v0.1\x00"...)
	signingInput = append(signingInput, unsigned...)
	valid := err == nil && len(signature) == ed25519.SignatureSize && ed25519.Verify(key, signingInput, signature)
	clear(unsigned)
	clear(signingInput)
	if !valid {
		return ErrInvalidRecord
	}
	return nil
}
