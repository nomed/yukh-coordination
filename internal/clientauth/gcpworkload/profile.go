package gcpworkload

import (
	"crypto/sha256"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/nomed/yukh-coordination/internal/clientauth"
)

// ProfileConfiguration is the closed, redacted identity shared by Storage,
// KMS, encrypted session custody and proof signing.
type ProfileConfiguration struct {
	profile          string
	bucket           string
	object           string
	encryption       KeyVersion
	signing          KeyVersion
	protection       kmspb.ProtectionLevel
	signerThumbprint [32]byte
}

func NewProfileConfiguration(profile, bucket, object string, encryption, signing KeyVersion, protection kmspb.ProtectionLevel, signerThumbprint [32]byte) (ProfileConfiguration, error) {
	if !validProfileName(profile) || !validBucket(bucket) || !validObject(object) || !validKeyVersion(encryption) || !validKeyVersion(signing) || encryption.value == signing.value || (protection != kmspb.ProtectionLevel_SOFTWARE && protection != kmspb.ProtectionLevel_HSM) || zero32(signerThumbprint) {
		return ProfileConfiguration{}, ErrInvalidContract
	}
	return ProfileConfiguration{profile: profile, bucket: bucket, object: object, encryption: encryption, signing: signing, protection: protection, signerThumbprint: signerThumbprint}, nil
}

func (ProfileConfiguration) String() string   { return "ProfileConfiguration{REDACTED}" }
func (ProfileConfiguration) GoString() string { return "ProfileConfiguration{REDACTED}" }

// Profile is the explicit RFC-0020 composition. It introduces no identity
// discovery, provider fallback, resource lifecycle or protocol behavior.
type Profile struct {
	credentials *CredentialStore
	signers     *CloudKMS
}

func NewProfile(configuration ProfileConfiguration, object CredentialObjectStore, cloudKMS *CloudKMS, operations OperationIDSource) (*Profile, error) {
	validated, err := NewProfileConfiguration(configuration.profile, configuration.bucket, configuration.object, configuration.encryption, configuration.signing, configuration.protection, configuration.signerThumbprint)
	if err != nil || object == nil || cloudKMS == nil || operations == nil {
		return nil, ErrInvalidContract
	}
	bucket, objectName, objectValid := object.Binding()
	profile, encryption, signing, protection, thumbprint, kmsValid := cloudKMS.Binding()
	if !objectValid || !kmsValid || bucket != validated.bucket || objectName != validated.object || profile != validated.profile || encryption.value != validated.encryption.value || signing.value != validated.signing.value || protection != validated.protection || thumbprint != validated.signerThumbprint {
		return nil, ErrInvalidContract
	}
	profileDigest := sha256.Sum256([]byte(profileDigestDomain + validated.profile))
	aad, err := NewAssociatedData(profileDigest, validated.bucket, validated.object, validated.encryption, validated.signing, validated.signerThumbprint)
	if err != nil {
		return nil, ErrInvalidContract
	}
	credentials, err := NewCredentialStore(validated.profile, object, cloudKMS, aad, operations)
	if err != nil {
		return nil, ErrInvalidContract
	}
	return &Profile{credentials: credentials, signers: cloudKMS}, nil
}

func (*Profile) String() string   { return "Profile{REDACTED}" }
func (*Profile) GoString() string { return "Profile{REDACTED}" }

func (p *Profile) CredentialStore() clientauth.CredentialStore {
	if p == nil {
		return nil
	}
	return p.credentials
}

func (p *Profile) ProofSignerStore() clientauth.ProofSignerStore {
	if p == nil {
		return nil
	}
	return p.signers
}
