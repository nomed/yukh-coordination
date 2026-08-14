package clientauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

type bootstrapIssuer struct{ issued *IssuedSession }

func (i bootstrapIssuer) Issue(context.Context, *BoundAccessToken, ProofSigner) (*IssuedSession, error) {
	return i.issued, nil
}

func TestBootstrapPersistsAndReopensExactSignerBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, signer := testSession(t, now)
	external, err := NewBoundAccessToken("header.payload.signature", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := NewIssuedSession(testParticipant, 1, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{}
	bootstrapper, err := NewBootstrapper(store, &memorySignerStore{signer: signer}, &testExternalTokenSource{expected: signer.jwk.Thumbprint(), token: external}, bootstrapIssuer{issued}, "default")
	if err != nil || bootstrapper.Bootstrap(context.Background()) != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	loaded, err := store.Load(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	record, _ := loaded.Record()
	if record.ParticipantInstanceID() != testParticipant || record.ProofKeyReference() != signer.reference || record.ProofJWKThumbprint() != signer.jwk.Thumbprint() {
		t.Fatal("stored binding changed")
	}
}

func TestBootstrapExplicitlyReplacesOnlyExpiredSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	expired, signer := testSession(t, now.Add(-2*time.Minute))
	store := &memoryCredentialStore{record: expired, revision: 4}
	external, _ := NewBoundAccessToken("header.payload.signature", now.Add(time.Minute))
	issued, _ := NewIssuedSession(testParticipant, 2, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)), now, now.Add(time.Minute))
	bootstrapper, err := NewBootstrapper(store, &memorySignerStore{signer: signer}, &testExternalTokenSource{expected: signer.jwk.Thumbprint(), token: external}, bootstrapIssuer{issued}, "default")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapper.now = func() time.Time { return now }
	if err := bootstrapper.Bootstrap(context.Background()); err != nil {
		t.Fatalf("replace expired session: %v", err)
	}
	loaded, err := store.Load(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	record, _ := loaded.Record()
	if record.SessionEpoch() != 2 || !record.ExpiresAt().Equal(now.Add(time.Minute)) || store.revision != 5 {
		t.Fatal("expired session was not replaced with the exact issued session")
	}
}

func TestBootstrapRejectsReplacementOfLiveSessionBeforeIssuance(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	live, signer := testSession(t, now)
	store := &memoryCredentialStore{record: live, revision: 2}
	bootstrapper, err := NewBootstrapper(store, &memorySignerStore{signer: signer}, &testExternalTokenSource{}, bootstrapIssuer{}, "default")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapper.now = func() time.Time { return now }
	if err := bootstrapper.Bootstrap(context.Background()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("bootstrap live session: %v", err)
	}
	if store.revision != 2 {
		t.Fatal("live session changed")
	}
}
