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
	signer, err := profile.ProofSignerStore().Open(context.Background(), record.ProofKeyReference())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignES256(context.Background(), []byte("header.payload")); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Delete(context.Background(), "server", revision); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Load(context.Background(), "server"); !errors.Is(err, clientauth.ErrCredentialMissing) {
		t.Fatalf("load after delete = %v", err)
	}
}

func TestProfileRejectsCrossWiredBindings(t *testing.T) {
	cloudKMS, encryption, signing, _ := kmsFixture(t)
	configuration, err := NewProfileConfiguration("server", "yukh-custody", "profiles/other", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, cloudKMS.public.Thumbprint())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProfile(configuration, &memoryObjectStore{}, cloudKMS, &fixedOperationIDs{}); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("cross-wired object error = %v", err)
	}
}

func TestProfileFormattingIsRedacted(t *testing.T) {
	cloudKMS, encryption, signing, _ := kmsFixture(t)
	configuration, _ := NewProfileConfiguration("server", "yukh-custody", "profiles/opaque", encryption, signing, kmspb.ProtectionLevel_SOFTWARE, cloudKMS.public.Thumbprint())
	if configuration.String() != "ProfileConfiguration{REDACTED}" {
		t.Fatal("configuration leaked")
	}
}
