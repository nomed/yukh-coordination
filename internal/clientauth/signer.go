package clientauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"math/big"
	"reflect"
)

const maxSigningInputBytes = 32_768

// PublicP256JWK is the closed public-key value shared with token sources and
// proof construction. Coordinates are copied on construction and access.
type PublicP256JWK struct {
	x [32]byte
	y [32]byte
}

func NewPublicP256JWK(x, y []byte) (PublicP256JWK, error) {
	if len(x) != 32 || len(y) != 32 {
		return PublicP256JWK{}, ErrInvalidCredential
	}
	public := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return PublicP256JWK{}, ErrInvalidCredential
	}
	var value PublicP256JWK
	copy(value.x[:], x)
	copy(value.y[:], y)
	return value, nil
}

func (j PublicP256JWK) Thumbprint() [32]byte {
	canonical := []byte(`{"crv":"P-256","kty":"EC","x":"` + base64.RawURLEncoding.EncodeToString(j.x[:]) + `","y":"` + base64.RawURLEncoding.EncodeToString(j.y[:]) + `"}`)
	return sha256.Sum256(canonical)
}

// Coordinates returns copies of the public coordinates for an explicitly
// configured token-source or signer adapter. It never exposes private material.
func (j PublicP256JWK) Coordinates() ([32]byte, [32]byte) { return j.x, j.y }

func (j PublicP256JWK) publicKey() (*ecdsa.PublicKey, error) {
	value, err := NewPublicP256JWK(j.x[:], j.y[:])
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(value.x[:]), Y: new(big.Int).SetBytes(value.y[:])}, nil
}

func (j PublicP256JWK) equalThumbprint(expected [32]byte) bool {
	actual := j.Thumbprint()
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

type ProofSigner interface {
	KeyReference() string
	PublicJWK() (PublicP256JWK, error)
	SignES256(context.Context, []byte) ([64]byte, error)
}

type ProofSignerStore interface {
	ProvisionP256(context.Context, string) (ProvisionedSigner, error)
	Open(context.Context, string) (ProofSigner, error)
	Retire(context.Context, string) error
}

type ProvisionedSigner struct {
	signer  ProofSigner
	created bool
}

func NewProvisionedSigner(signer ProofSigner, created bool) (ProvisionedSigner, error) {
	if nilInterface(signer) {
		return ProvisionedSigner{}, ErrInvalidCredential
	}
	return ProvisionedSigner{signer: signer, created: created}, nil
}

func (p ProvisionedSigner) Signer() ProofSigner { return p.signer }
func (p ProvisionedSigner) Created() bool       { return p.created }

func validSignature(publicKey *ecdsa.PublicKey, signingInput []byte, signature [64]byte) bool {
	if len(signingInput) == 0 || len(signingInput) > maxSigningInputBytes {
		return false
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(publicKey.Params().N) >= 0 || s.Cmp(publicKey.Params().N) >= 0 {
		return false
	}
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(publicKey, digest[:], r, s)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
