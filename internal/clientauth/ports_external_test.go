package clientauth_test

import (
	"context"

	"github.com/nomed/yukh-coordination/internal/clientauth"
)

// These compile-time adapters prove that the neutral ports are implementable
// outside package clientauth without access to private key material.
type externalCredentialStore struct{}

func (externalCredentialStore) Load(context.Context, string) (clientauth.StoredSession, error) {
	return clientauth.StoredSession{}, clientauth.ErrCredentialMissing
}
func (externalCredentialStore) Save(_ context.Context, _ string, expected clientauth.Revision, record *clientauth.SessionRecord) (clientauth.Revision, error) {
	_, _ = expected.ProviderValue()
	_ = expected.IsAbsent()
	_, _, _ = record.Credential(), record.ProofKeyReference(), record.ProofJWKThumbprint()
	return clientauth.Revision{}, clientauth.ErrCredentialStore
}
func (externalCredentialStore) Delete(_ context.Context, _ string, expected clientauth.Revision) error {
	_, _ = expected.ProviderValue()
	return clientauth.ErrCredentialStore
}

type externalProofSignerStore struct{}

type externalProofSigner struct{}

func (externalProofSigner) KeyReference() string { return "external:key:version:1" }
func (externalProofSigner) PublicJWK() (clientauth.PublicP256JWK, error) {
	return clientauth.PublicP256JWK{}, clientauth.ErrProofSigner
}
func (externalProofSigner) SignES256(context.Context, []byte) ([64]byte, error) {
	return [64]byte{}, clientauth.ErrProofSigner
}

func (externalProofSignerStore) ProvisionP256(context.Context, string) (clientauth.ProvisionedSigner, error) {
	return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
}
func (externalProofSignerStore) Open(context.Context, string) (clientauth.ProofSigner, error) {
	return nil, clientauth.ErrProofKeyMissing
}
func (externalProofSignerStore) Retire(context.Context, string) error {
	return clientauth.ErrProofSigner
}

type externalTokenSource struct{}

func (externalTokenSource) Acquire(_ context.Context, key clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	_, _ = key.Coordinates()
	return nil, clientauth.ErrExternalToken
}

var (
	_ clientauth.CredentialStore     = externalCredentialStore{}
	_ clientauth.ProofSigner         = externalProofSigner{}
	_ clientauth.ProofSignerStore    = externalProofSignerStore{}
	_ clientauth.ExternalTokenSource = externalTokenSource{}
)
