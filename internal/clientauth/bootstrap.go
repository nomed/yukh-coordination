package clientauth

import (
	"context"
	"errors"
	"time"
)

// IssuedSession is the closed, proof-bound relay response accepted by Bootstrapper.
type IssuedSession struct {
	participant string
	epoch       uint64
	token       string
	issuedAt    time.Time
	expiresAt   time.Time
}

func NewIssuedSession(participant string, epoch uint64, token string, issuedAt, expiresAt time.Time) (*IssuedSession, error) {
	record, err := NewSessionRecord(participant, epoch, token, issuedAt, expiresAt, "bootstrap:validation", [32]byte{1})
	if err != nil {
		return nil, ErrInvalidCredential
	}
	return &IssuedSession{participant: record.ParticipantInstanceID(), epoch: record.SessionEpoch(), token: record.Credential(), issuedAt: record.IssuedAt(), expiresAt: record.ExpiresAt()}, nil
}

// SessionIssuer owns the exact relay bootstrap exchange. Credentials are
// available only across this adapter boundary and must never be formatted.
type SessionIssuer interface {
	Issue(context.Context, *BoundAccessToken, ProofSigner) (*IssuedSession, error)
}

type Bootstrapper struct {
	credentials CredentialStore
	signers     ProofSignerStore
	tokens      ExternalTokenSource
	issuer      SessionIssuer
	profile     string
	now         func() time.Time
}

func NewBootstrapper(credentials CredentialStore, signers ProofSignerStore, tokens ExternalTokenSource, issuer SessionIssuer, profile string) (*Bootstrapper, error) {
	if nilInterface(credentials) || nilInterface(signers) || nilInterface(tokens) || nilInterface(issuer) || validateProfile(profile) != nil {
		return nil, ErrInvalidCredential
	}
	return &Bootstrapper{credentials: credentials, signers: signers, tokens: tokens, issuer: issuer, profile: profile, now: time.Now}, nil
}

// Bootstrap executes the accepted cross-provider saga and reports success only
// after an exact custody reload and signer-binding verification.
func (b *Bootstrapper) Bootstrap(ctx context.Context) error {
	if b == nil || ctx == nil || ctx.Err() != nil || b.now == nil {
		return ErrInvalidCredential
	}
	expected := AbsentRevision()
	stored, err := b.credentials.Load(ctx, b.profile)
	switch {
	case err == nil:
		record, recordErr := stored.Record()
		if recordErr != nil {
			return ErrCredentialStore
		}
		if record.ExpiresAt().After(b.now().UTC()) {
			return ErrCredentialConflict
		}
		expected = stored.Revision()
	case errors.Is(err, ErrCredentialMissing):
	case err != nil:
		return sanitizeStoreError(err)
	}
	provisioned, err := b.signers.ProvisionP256(ctx, b.profile)
	if err != nil {
		return sanitizeSignerError(err)
	}
	signer := provisioned.Signer()
	if nilInterface(signer) {
		return ErrProofSigner
	}
	cleanup := func() {
		if provisioned.Created() {
			_ = b.signers.Retire(context.WithoutCancel(ctx), signer.KeyReference())
		}
	}
	jwk, err := signer.PublicJWK()
	if err != nil || signer.KeyReference() == "" {
		cleanup()
		return ErrProofSigner
	}
	external, err := b.tokens.Acquire(ctx, jwk)
	if err != nil || external == nil || !external.ExpiresAt().After(time.Now().UTC()) {
		cleanup()
		return ErrExternalToken
	}
	issued, err := b.issuer.Issue(ctx, external, signer)
	if err != nil || issued == nil {
		// The relay outcome is ambiguous after the exchange begins; retain the key.
		return ErrExternalToken
	}
	record, err := NewSessionRecord(issued.participant, issued.epoch, issued.token, issued.issuedAt, issued.expiresAt, signer.KeyReference(), jwk.Thumbprint())
	if err != nil {
		return ErrInvalidCredential
	}
	if _, err = b.credentials.Save(ctx, b.profile, expected, record); err != nil {
		return sanitizeStoreError(err)
	}
	stored, err = b.credentials.Load(ctx, b.profile)
	if err != nil {
		return sanitizeStoreError(err)
	}
	loaded, err := stored.Record()
	if err != nil || loaded.ProofKeyReference() != signer.KeyReference() || loaded.ProofJWKThumbprint() != jwk.Thumbprint() || loaded.ParticipantInstanceID() != issued.participant || loaded.SessionEpoch() != issued.epoch {
		return ErrCredentialStore
	}
	opened, err := b.signers.Open(ctx, loaded.ProofKeyReference())
	if err != nil || nilInterface(opened) {
		return ErrProofSigner
	}
	openedJWK, err := opened.PublicJWK()
	if err != nil || opened.KeyReference() != loaded.ProofKeyReference() || openedJWK.Thumbprint() != loaded.ProofJWKThumbprint() {
		return ErrProofKeyMissing
	}
	return nil
}
