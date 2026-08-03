package primitives

import "crypto/rand"

type CryptoTokenIDSource struct{}

func (CryptoTokenIDSource) NewTokenID() ([16]byte, error) {
	var value [16]byte
	_, err := rand.Read(value[:])
	return value, err
}
