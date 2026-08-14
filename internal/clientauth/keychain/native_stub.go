//go:build !darwin || !cgo

package keychain

import "context"

// nativeProvider is deliberately unavailable outside the supported native
// Keychain boundary. It never attempts a file, environment, or provider fallback.
type nativeProvider struct{}

func newNativeProvider() provider { return nativeProvider{} }

func (nativeProvider) Lookup(context.Context, Binding) ([]item, error) {
	return nil, errUnavailable
}

func (nativeProvider) Create(context.Context, Binding, []byte) (bool, error) {
	return false, errUnavailable
}
