package gcpworkload

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeKMS struct {
	encryption        string
	signing           string
	private           *ecdsa.PrivateKey
	publicPEM         string
	protection        kmspb.ProtectionLevel
	signatureOverride []byte
}

func (f *fakeKMS) version(_ context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	algorithm := kmspb.CryptoKeyVersion_AES_256_GCM
	if name == f.signing {
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	}
	return &kmspb.CryptoKeyVersion{Name: name, State: kmspb.CryptoKeyVersion_ENABLED, Algorithm: algorithm, ProtectionLevel: f.protection}, nil
}
func (f *fakeKMS) publicKey(context.Context, string) (*kmspb.PublicKey, error) {
	return &kmspb.PublicKey{Name: f.signing, Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, ProtectionLevel: f.protection, Pem: f.publicPEM, PemCrc32C: crcValue(Checksum([]byte(f.publicPEM)))}, nil
}
func (*fakeKMS) rawEncrypt(_ context.Context, request *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	gcm, _ := cipher.NewGCM(block)
	iv := []byte("0123456789ab")
	ciphertext := gcm.Seal(nil, iv, request.Plaintext, request.AdditionalAuthenticatedData)
	return &kmspb.RawEncryptResponse{Ciphertext: ciphertext, InitializationVector: iv, TagLength: 16, CiphertextCrc32C: crcValue(Checksum(ciphertext)), InitializationVectorCrc32C: crcValue(Checksum(iv)), VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true, Name: request.Name, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE}, nil
}
func (*fakeKMS) rawDecrypt(_ context.Context, request *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	gcm, _ := cipher.NewGCM(block)
	plaintext, err := gcm.Open(nil, request.InitializationVector, request.Ciphertext, request.AdditionalAuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &kmspb.RawDecryptResponse{Plaintext: plaintext, PlaintextCrc32C: crcValue(Checksum(plaintext)), ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE, VerifiedCiphertextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true, VerifiedInitializationVectorCrc32C: true}, nil
}
func (f *fakeKMS) sign(_ context.Context, request *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if f.signatureOverride != nil {
		signature := append([]byte(nil), f.signatureOverride...)
		return &kmspb.AsymmetricSignResponse{Signature: signature, SignatureCrc32C: crcValue(Checksum(signature)), VerifiedDigestCrc32C: true, Name: f.signing, ProtectionLevel: f.protection}, nil
	}
	digest := request.Digest.GetSha256()
	r, s, err := ecdsa.Sign(bytes.NewReader(bytes.Repeat([]byte{3}, 256)), f.private, digest)
	if err != nil {
		return nil, err
	}
	signature, _ := asn1.Marshal(derSignature{r, s})
	return &kmspb.AsymmetricSignResponse{Signature: signature, SignatureCrc32C: wrapperspb.Int64(int64(Checksum(signature).ProviderValue())), VerifiedDigestCrc32C: true, Name: f.signing, ProtectionLevel: f.protection}, nil
}

type scriptedKMS struct {
	*fakeKMS
	versionErrors []error
	versionCalls  int
}

func (s *scriptedKMS) version(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	s.versionCalls++
	if len(s.versionErrors) > 0 {
		err := s.versionErrors[0]
		s.versionErrors = s.versionErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	return s.fakeKMS.version(ctx, name)
}

func TestCloudKMSRawAEADAndSigner(t *testing.T) {
	kmsAdapter, encryption, signing, aad := kmsFixture(t)
	plain, _ := NewPlaintext([]byte("session-secret"))
	ciphertext, err := kmsAdapter.Encrypt(context.Background(), encryption, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := kmsAdapter.Decrypt(context.Background(), encryption, ciphertext, aad)
	if err != nil {
		t.Fatal(err)
	}
	value, _, _ := opened.ProviderValue()
	if string(value) != "session-secret" {
		t.Fatal("plaintext mismatch")
	}
	provisioned, err := kmsAdapter.ProvisionP256(context.Background(), "server")
	if err != nil || provisioned.Created() {
		t.Fatalf("provision: %v created=%v", err, provisioned.Created())
	}
	signature, err := kmsAdapter.SignES256(context.Background(), []byte("header.payload"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("header.payload"))
	if !ecdsa.Verify(kmsAdapter.publicECDSA, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("invalid JOSE signature")
	}
	if kmsAdapter.KeyReference() != signing.value {
		t.Fatal("wrong key reference")
	}
}

func TestCloudKMSFailsClosedOnProviderEvidence(t *testing.T) {
	backend, encryption, signing := kmsBackendFixture(t)
	backend.publicPEM += "corrupt"
	if _, err := newCloudKMS(context.Background(), backend, "server", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, [32]byte{1}, time.Second, 3*time.Second, time.Millisecond, 2); err == nil {
		t.Fatal("accepted corrupt public-key evidence")
	}
}

func TestCloudKMSRejectsMalformedDERSignature(t *testing.T) {
	adapter, _, _, _ := kmsFixture(t)
	adapter.backend.(*fakeKMS).signatureOverride = []byte{0x30, 0x01, 0x00}
	if _, err := adapter.SignES256(context.Background(), []byte("header.payload")); err == nil {
		t.Fatal("accepted malformed DER")
	}
}

func TestCloudKMSRetriesOnlyTransientErrors(t *testing.T) {
	backend, encryption, signing := kmsBackendFixture(t)
	parsed, _, _ := validatePublicKey(mustPublicKey(t, backend), signing.value, kmspb.ProtectionLevel_SOFTWARE)
	transient := &scriptedKMS{fakeKMS: backend, versionErrors: []error{status.Error(codes.Unavailable, "transient")}}
	if _, err := newCloudKMS(context.Background(), transient, "server", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, parsed.Thumbprint(), time.Second, 3*time.Second, time.Millisecond, 2); err != nil {
		t.Fatalf("transient retry: %v", err)
	}
	if transient.versionCalls != 3 {
		t.Fatalf("version calls = %d", transient.versionCalls)
	}
	permanent := &scriptedKMS{fakeKMS: backend, versionErrors: []error{status.Error(codes.PermissionDenied, "denied")}}
	if _, err := newCloudKMS(context.Background(), permanent, "server", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, parsed.Thumbprint(), time.Second, 3*time.Second, time.Millisecond, 2); err == nil {
		t.Fatal("accepted permanent provider error")
	}
	if permanent.versionCalls != 1 {
		t.Fatalf("permanent calls = %d", permanent.versionCalls)
	}
}

func kmsFixture(t *testing.T) (*CloudKMS, KeyVersion, KeyVersion, AssociatedData) {
	backend, encryption, signing := kmsBackendFixture(t)
	parsed, _, err := validatePublicKey(mustPublicKey(t, backend), signing.value, kmspb.ProtectionLevel_SOFTWARE)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newCloudKMS(context.Background(), backend, "server", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, parsed.Thumbprint(), time.Second, 3*time.Second, time.Millisecond, 2)
	if err != nil {
		t.Fatal(err)
	}
	profile := sha256.Sum256([]byte(profileDigestDomain + "server"))
	aad, err := NewAssociatedData(profile, "yukh-custody", "profiles/opaque", encryption, signing, adapter.public.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	return adapter, encryption, signing, aad
}

func mustPublicKey(t *testing.T, backend *fakeKMS) *kmspb.PublicKey {
	t.Helper()
	value, err := backend.publicKey(context.Background(), backend.signing)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func kmsBackendFixture(t *testing.T) (*fakeKMS, KeyVersion, KeyVersion) {
	t.Helper()
	encryption, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/session/cryptoKeyVersions/1")
	signing, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/proof/cryptoKeyVersions/2")
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: new(big.Int).SetInt64(7)}
	private.PublicKey.X, private.PublicKey.Y = elliptic.P256().ScalarBaseMult(private.D.Bytes())
	der, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return &fakeKMS{encryption: encryption.value, signing: signing.value, private: private, publicPEM: publicPEM, protection: kmspb.ProtectionLevel_SOFTWARE}, encryption, signing
}
