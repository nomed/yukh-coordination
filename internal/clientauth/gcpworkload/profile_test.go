package gcpworkload

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/nomed/yukh-coordination/internal/clientauth"
)

func TestProfileEndToEndSyntheticProviders(t *testing.T) {
	cloudKMS, encryption, signing, _ := kmsFixture(t)
	configuration, err := NewProfileConfiguration("server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, cloudKMS.public.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	object := &memoryObjectStore{}
	profile, err := NewProfile(configuration, object, cloudKMS, &fixedOperationIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, template := credentialFixture(t)
	record, err := clientauth.NewSessionRecord(template.ParticipantInstanceID(), template.SessionEpoch(), template.Credential(), template.IssuedAt(), template.ExpiresAt(), signing.value, cloudKMS.public.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	credentials := profile.CredentialStore()
	revision, err := credentials.Save(context.Background(), "server", clientauth.AbsentRevision(), record)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := credentials.Load(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	loadedRecord, err := loaded.Record()
	if err != nil || !sameRecord(record, loadedRecord) {
		t.Fatal("composed record mismatch")
	}
	replacement, err := clientauth.NewSessionRecord(record.ParticipantInstanceID(), record.SessionEpoch()+1, record.Credential(), record.IssuedAt(), record.ExpiresAt(), signing.value, cloudKMS.public.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	nextRevision, err := credentials.Save(context.Background(), "server", revision, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Save(context.Background(), "server", revision, replacement); !errors.Is(err, clientauth.ErrCredentialConflict) {
		t.Fatalf("stale replacement error = %v", err)
	}
	provisioned, err := profile.ProofSignerStore().ProvisionP256(context.Background(), "server")
	if err != nil || provisioned.Created() {
		t.Fatalf("provision signer: %v created=%v", err, provisioned.Created())
	}
	signer, err := profile.ProofSignerStore().Open(context.Background(), record.ProofKeyReference())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignES256(context.Background(), []byte("header.payload")); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Delete(context.Background(), "server", nextRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Load(context.Background(), "server"); !errors.Is(err, clientauth.ErrCredentialMissing) {
		t.Fatalf("load after delete = %v", err)
	}
}

type profileBoundObject struct {
	*memoryObjectStore
	bucket string
	object string
}

func (o profileBoundObject) Binding() (string, string, bool) {
	return o.bucket, o.object, true
}

func TestProfileRejectsCrossWiredBindings(t *testing.T) {
	cloudKMS, encryption, signing, _ := kmsFixture(t)
	otherEncryption, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/other-session/cryptoKeyVersions/3")
	otherSigning, _ := NewKeyVersion("projects/123456/locations/europe-west1/keyRings/yukh/cryptoKeys/other-proof/cryptoKeyVersions/4")
	thumbprint := cloudKMS.public.Thumbprint()
	otherThumbprint := thumbprint
	otherThumbprint[0] ^= 0xff
	tests := []struct {
		name       string
		profile    string
		bucket     string
		object     string
		encryption KeyVersion
		signing    KeyVersion
		protection kmspb.ProtectionLevel
		thumbprint [32]byte
		store      CredentialObjectStore
	}{
		{"profile", "other", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, &memoryObjectStore{}},
		{"bucket", "server", "other-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, &memoryObjectStore{}},
		{"object", "server", "yukh-custody", "profiles/other", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, &memoryObjectStore{}},
		{"encryption", "server", "yukh-custody", "profiles/opaque", otherEncryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, &memoryObjectStore{}},
		{"signing", "server", "yukh-custody", "profiles/opaque", encryption, otherSigning, kmspb.ProtectionLevel_SOFTWARE, thumbprint, &memoryObjectStore{}},
		{"protection", "server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_HSM, thumbprint, &memoryObjectStore{}},
		{"thumbprint", "server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, otherThumbprint, &memoryObjectStore{}},
		{"store-bucket", "server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, profileBoundObject{&memoryObjectStore{}, "other-custody", "profiles/opaque"}},
		{"store-object", "server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, thumbprint, profileBoundObject{&memoryObjectStore{}, "yukh-custody", "profiles/other"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration, err := NewProfileConfiguration(test.profile, test.bucket, test.object, test.encryption, test.signing, test.protection, test.thumbprint)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewProfile(configuration, test.store, cloudKMS, &fixedOperationIDs{}); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("cross-wired binding error = %v", err)
			}
		})
	}
}

func TestProfileFormattingIsRedacted(t *testing.T) {
	cloudKMS, encryption, signing, _ := kmsFixture(t)
	configuration, _ := NewProfileConfiguration("server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, cloudKMS.public.Thumbprint())
	if configuration.String() != "ProfileConfiguration{REDACTED}" {
		t.Fatal("configuration leaked")
	}
}
