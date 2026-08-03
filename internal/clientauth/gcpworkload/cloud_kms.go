package gcpworkload

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"github.com/nomed/yukh-coordination/internal/clientauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type noRetry struct{}

func (noRetry) Retry(error) (time.Duration, bool) { return 0, false }

var noSDKRetry = gax.WithRetry(func() gax.Retryer { return noRetry{} })

type kmsBackend interface {
	version(context.Context, string) (*kmspb.CryptoKeyVersion, error)
	publicKey(context.Context, string) (*kmspb.PublicKey, error)
	rawEncrypt(context.Context, *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error)
	rawDecrypt(context.Context, *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error)
	sign(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error)
}

type sdkKMSBackend struct{ client *kms.KeyManagementClient }

func (b sdkKMSBackend) version(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	return b.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name}, noSDKRetry)
}
func (b sdkKMSBackend) publicKey(ctx context.Context, name string) (*kmspb.PublicKey, error) {
	return b.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name}, noSDKRetry)
}
func (b sdkKMSBackend) rawEncrypt(ctx context.Context, request *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	return b.client.RawEncrypt(ctx, request, noSDKRetry)
}
func (b sdkKMSBackend) rawDecrypt(ctx context.Context, request *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	return b.client.RawDecrypt(ctx, request, noSDKRetry)
}
func (b sdkKMSBackend) sign(ctx context.Context, request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return b.client.AsymmetricSign(ctx, request, noSDKRetry)
}

// CloudKMS owns the two immutable RFC-0020 key-version capabilities. It never
// constructs a client, discovers credentials or mutates key lifecycle state.
type CloudKMS struct {
	backend      kmsBackend
	profile      string
	encryption   KeyVersion
	signing      KeyVersion
	protection   kmspb.ProtectionLevel
	public       clientauth.PublicP256JWK
	publicECDSA  *ecdsa.PublicKey
	thumbprint   [32]byte
	timeout      time.Duration
	totalTimeout time.Duration
	retryDelay   time.Duration
	maxAttempts  int
}

func NewCloudKMS(ctx context.Context, client *kms.KeyManagementClient, profile string, encryption, signing KeyVersion, protection kmspb.ProtectionLevel, expectedThumbprint [32]byte, requestTimeout, totalTimeout, retryDelay time.Duration, maxAttempts int) (*CloudKMS, error) {
	if client == nil {
		return nil, ErrInvalidContract
	}
	return newCloudKMS(ctx, sdkKMSBackend{client}, profile, encryption, signing, protection, expectedThumbprint, requestTimeout, totalTimeout, retryDelay, maxAttempts)
}

func newCloudKMS(ctx context.Context, backend kmsBackend, profile string, encryption, signing KeyVersion, protection kmspb.ProtectionLevel, expectedThumbprint [32]byte, requestTimeout, totalTimeout, retryDelay time.Duration, maxAttempts int) (*CloudKMS, error) {
	if backend == nil || !validProfileName(profile) || !validKeyVersion(encryption) || !validKeyVersion(signing) || encryption.value == signing.value || zero32(expectedThumbprint) || (protection != kmspb.ProtectionLevel_SOFTWARE && protection != kmspb.ProtectionLevel_HSM) || requestTimeout <= 0 || totalTimeout < requestTimeout || retryDelay <= 0 || retryDelay > requestTimeout || maxAttempts < 1 || maxAttempts > 5 {
		return nil, ErrInvalidContract
	}
	value := &CloudKMS{backend: backend, profile: profile, encryption: encryption, signing: signing, protection: protection, timeout: requestTimeout, totalTimeout: totalTimeout, retryDelay: retryDelay, maxAttempts: maxAttempts}
	enc, err := value.getVersion(ctx, encryption.value)
	if err != nil || enc == nil || enc.Name != encryption.value || enc.State != kmspb.CryptoKeyVersion_ENABLED || enc.Algorithm != kmspb.CryptoKeyVersion_AES_256_GCM || enc.ProtectionLevel != protection {
		return nil, ErrUnavailable
	}
	sig, err := value.getVersion(ctx, signing.value)
	if err != nil || sig == nil || sig.Name != signing.value || sig.State != kmspb.CryptoKeyVersion_ENABLED || sig.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 || sig.ProtectionLevel != protection {
		return nil, ErrUnavailable
	}
	response, err := value.getPublic(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	jwk, public, err := validatePublicKey(response, signing.value, protection)
	if err != nil {
		return nil, ErrIntegrity
	}
	actualThumbprint := jwk.Thumbprint()
	if subtle.ConstantTimeCompare(actualThumbprint[:], expectedThumbprint[:]) != 1 {
		return nil, ErrIntegrity
	}
	value.public, value.publicECDSA = jwk, public
	value.thumbprint = expectedThumbprint
	return value, nil
}

func (k *CloudKMS) Encrypt(ctx context.Context, version KeyVersion, plaintext Plaintext, aad AssociatedData) (RawCiphertext, error) {
	plain, plainCRC, ok := plaintext.ProviderValue()
	canonical, aadErr := aad.Canonical()
	if k == nil || !ok || aadErr != nil || version.value != k.encryption.value || aad.encryptionVersion.value != k.encryption.value || aad.signingVersion.value != k.signing.value || len(plain)+len(canonical) > 8192 {
		return RawCiphertext{}, ErrInvalidContract
	}
	request := &kmspb.RawEncryptRequest{Name: k.encryption.value, Plaintext: plain, AdditionalAuthenticatedData: canonical, PlaintextCrc32C: crcValue(plainCRC), AdditionalAuthenticatedDataCrc32C: crcValue(Checksum(canonical))}
	var response *kmspb.RawEncryptResponse
	err := k.attempt(ctx, func(call context.Context) error {
		var err error
		response, err = k.backend.rawEncrypt(call, request)
		return err
	})
	if err != nil {
		return RawCiphertext{}, ErrUnavailable
	}
	if response == nil || response.Name != k.encryption.value || response.ProtectionLevel != k.protection || !response.VerifiedPlaintextCrc32C || !response.VerifiedAdditionalAuthenticatedDataCrc32C || response.VerifiedInitializationVectorCrc32C || response.TagLength != standardTagBytes || !validProviderCRC(response.Ciphertext, response.CiphertextCrc32C) || !validProviderCRC(response.InitializationVector, response.InitializationVectorCrc32C) {
		return RawCiphertext{}, ErrIntegrity
	}
	return NewRawCiphertext(k.encryption, response.InitializationVector, uint16(response.TagLength), response.Ciphertext)
}

func (k *CloudKMS) Decrypt(ctx context.Context, version KeyVersion, ciphertext RawCiphertext, aad AssociatedData) (Plaintext, error) {
	canonical, aadErr := aad.Canonical()
	raw := ciphertext.Ciphertext()
	iv := ciphertext.IV()
	if k == nil || aadErr != nil || version.value != k.encryption.value || aad.encryptionVersion.value != k.encryption.value || aad.signingVersion.value != k.signing.value || ciphertext.KeyVersion().value != k.encryption.value || ciphertext.TagLength() != standardTagBytes {
		return Plaintext{}, ErrInvalidContract
	}
	request := &kmspb.RawDecryptRequest{Name: k.encryption.value, Ciphertext: raw, AdditionalAuthenticatedData: canonical, InitializationVector: iv, TagLength: int32(standardTagBytes), CiphertextCrc32C: crcValue(Checksum(raw)), AdditionalAuthenticatedDataCrc32C: crcValue(Checksum(canonical)), InitializationVectorCrc32C: crcValue(Checksum(iv))}
	var response *kmspb.RawDecryptResponse
	err := k.attempt(ctx, func(call context.Context) error {
		var err error
		response, err = k.backend.rawDecrypt(call, request)
		return err
	})
	if err != nil {
		return Plaintext{}, ErrUnavailable
	}
	if response == nil || response.ProtectionLevel != k.protection || !response.VerifiedCiphertextCrc32C || !response.VerifiedAdditionalAuthenticatedDataCrc32C || !response.VerifiedInitializationVectorCrc32C || !validProviderCRC(response.Plaintext, response.PlaintextCrc32C) {
		return Plaintext{}, ErrIntegrity
	}
	return NewPlaintext(response.Plaintext)
}

func (k *CloudKMS) ProvisionP256(ctx context.Context, profile string) (clientauth.ProvisionedSigner, error) {
	if k == nil || profile != k.profile {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	if _, err := k.Open(ctx, k.signing.value); err != nil {
		return clientauth.ProvisionedSigner{}, clientauth.ErrProofSigner
	}
	return clientauth.NewProvisionedSigner(k, false)
}
func (k *CloudKMS) Open(ctx context.Context, reference string) (clientauth.ProofSigner, error) {
	if k == nil || reference != k.signing.value {
		return nil, clientauth.ErrProofSigner
	}
	version, err := k.getVersion(ctx, reference)
	if err != nil || version.State != kmspb.CryptoKeyVersion_ENABLED || version.Name != reference || version.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 || version.ProtectionLevel != k.protection {
		return nil, clientauth.ErrProofSigner
	}
	response, err := k.getPublic(ctx)
	if err != nil {
		return nil, clientauth.ErrProofSigner
	}
	jwk, _, err := validatePublicKey(response, reference, k.protection)
	actual := jwk.Thumbprint()
	if err != nil || subtle.ConstantTimeCompare(actual[:], k.thumbprint[:]) != 1 {
		return nil, clientauth.ErrProofSigner
	}
	return k, nil
}
func (*CloudKMS) Retire(context.Context, string) error { return clientauth.ErrProofSigner }
func (k *CloudKMS) KeyReference() string {
	if k == nil {
		return ""
	}
	return k.signing.value
}
func (k *CloudKMS) PublicJWK() (clientauth.PublicP256JWK, error) {
	if k == nil {
		return clientauth.PublicP256JWK{}, clientauth.ErrProofSigner
	}
	return k.public, nil
}

func (k *CloudKMS) SignES256(ctx context.Context, input []byte) ([64]byte, error) {
	var output [64]byte
	if k == nil || len(input) == 0 || len(input) > 32768 {
		return output, clientauth.ErrProofSigner
	}
	digest := sha256.Sum256(input)
	request := &kmspb.AsymmetricSignRequest{Name: k.signing.value, Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}}, DigestCrc32C: crcValue(Checksum(digest[:]))}
	var response *kmspb.AsymmetricSignResponse
	if err := k.attempt(ctx, func(call context.Context) error {
		var err error
		response, err = k.backend.sign(call, request)
		return err
	}); err != nil {
		return output, clientauth.ErrProofSigner
	}
	if response == nil || response.Name != k.signing.value || response.ProtectionLevel != k.protection || !response.VerifiedDigestCrc32C || response.VerifiedDataCrc32C || !validProviderCRC(response.Signature, response.SignatureCrc32C) {
		return output, clientauth.ErrProofSigner
	}
	r, s, err := parseDERSignature(response.Signature, k.publicECDSA.Params().N)
	if err != nil || !ecdsa.Verify(k.publicECDSA, digest[:], r, s) {
		return output, clientauth.ErrProofSigner
	}
	r.FillBytes(output[:32])
	s.FillBytes(output[32:])
	return output, nil
}

func (k *CloudKMS) getVersion(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	var out *kmspb.CryptoKeyVersion
	err := k.attempt(ctx, func(call context.Context) error { var err error; out, err = k.backend.version(call, name); return err })
	return out, err
}
func (k *CloudKMS) getPublic(ctx context.Context) (*kmspb.PublicKey, error) {
	var out *kmspb.PublicKey
	err := k.attempt(ctx, func(call context.Context) error {
		var err error
		out, err = k.backend.publicKey(call, k.signing.value)
		return err
	})
	return out, err
}
func (k *CloudKMS) attempt(ctx context.Context, call func(context.Context) error) error {
	total, totalCancel := context.WithTimeout(ctx, k.totalTimeout)
	defer totalCancel()
	var err error
	for i := 0; i < k.maxAttempts; i++ {
		operation, cancel := context.WithTimeout(total, k.timeout)
		err = call(operation)
		cancel()
		if err == nil {
			return nil
		}
		if total.Err() != nil || !retryableKMSError(err) || i+1 == k.maxAttempts {
			return err
		}
		delay := k.retryDelay << i
		timer := time.NewTimer(delay)
		select {
		case <-total.Done():
			timer.Stop()
			return total.Err()
		case <-timer.C:
		}
	}
	return err
}

func retryableKMSError(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Aborted:
		return true
	default:
		return false
	}
}
func crcValue(value CRC32C) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(value.ProviderValue()))
}
func validProviderCRC(value []byte, checksum *wrapperspb.Int64Value) bool {
	return checksum != nil && checksum.Value >= 0 && checksum.Value <= 1<<32-1 && int64(Checksum(value).ProviderValue()) == checksum.Value
}

func validatePublicKey(value *kmspb.PublicKey, name string, protection kmspb.ProtectionLevel) (clientauth.PublicP256JWK, *ecdsa.PublicKey, error) {
	if value == nil || value.Name != name || value.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 || value.ProtectionLevel != protection || !validProviderCRC([]byte(value.Pem), value.PemCrc32C) {
		return clientauth.PublicP256JWK{}, nil, ErrIntegrity
	}
	block, rest := pem.Decode([]byte(value.Pem))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return clientauth.PublicP256JWK{}, nil, ErrIntegrity
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || public.Curve != elliptic.P256() || public.X.Sign() <= 0 || public.Y.Sign() <= 0 {
		return clientauth.PublicP256JWK{}, nil, ErrIntegrity
	}
	canonical, _ := x509.MarshalPKIXPublicKey(public)
	if subtle.ConstantTimeCompare(canonical, block.Bytes) != 1 {
		return clientauth.PublicP256JWK{}, nil, ErrIntegrity
	}
	jwk, err := clientauth.NewPublicP256JWK(public.X.FillBytes(make([]byte, 32)), public.Y.FillBytes(make([]byte, 32)))
	return jwk, public, err
}

type derSignature struct{ R, S *big.Int }

func parseDERSignature(raw []byte, order *big.Int) (*big.Int, *big.Int, error) {
	var value derSignature
	rest, err := asn1.Unmarshal(raw, &value)
	if err != nil || len(rest) != 0 || value.R == nil || value.S == nil || value.R.Sign() <= 0 || value.S.Sign() <= 0 || value.R.Cmp(order) >= 0 || value.S.Cmp(order) >= 0 {
		return nil, nil, ErrIntegrity
	}
	canonical, _ := asn1.Marshal(value)
	if !bytes.Equal(canonical, raw) {
		return nil, nil, ErrIntegrity
	}
	return value.R, value.S, nil
}

var _ RawAEAD = (*CloudKMS)(nil)
var _ clientauth.ProofSignerStore = (*CloudKMS)(nil)
var _ clientauth.ProofSigner = (*CloudKMS)(nil)
