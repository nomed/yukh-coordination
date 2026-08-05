package clientauth

import (
	"bytes"
	"context"
	"encoding/base64"
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
