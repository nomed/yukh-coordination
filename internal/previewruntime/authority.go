// Package previewruntime composes the bounded, local-only identity boundary for
// the first usable preview. It is not a production identity provider.
package previewruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const tokenLifetime = 10 * time.Minute

var localAgentName = regexp.MustCompile(`^agent-[a-z](?:[a-z0-9-]{0,40}[a-z0-9])?$`)

func validLocalAgent(value string) bool {
	return len(value) <= 48 && localAgentName.MatchString(value)
}

var ErrIdentityUnavailable = errors.New("preview runtime: identity unavailable")

type ExternalToken struct {
	Credential string
	ExpiresAt  time.Time
}

type externalRecord struct {
	slot       string
	thumbprint [sha256.Size]byte
	expiresAt  time.Time
	consumed   bool
}

type sessionRecord struct {
	identity   httpapi.Identity
	thumbprint [sha256.Size]byte
	expiresAt  time.Time
}

// Authority owns only run-scoped opaque tokens and DPoP replay state. External
// tokens are single-use and are bound before issuance to the requesting key.
type Authority struct {
	mu       sync.Mutex
	external map[[sha256.Size]byte]externalRecord
	sessions map[[sha256.Size]byte]sessionRecord
	replays  map[string]time.Time
	dpop     *identity.DPoPVerifier
	random   io.Reader
	now      func() time.Time
	newID    func() (uuid.UUID, error)
}

func NewAuthority() *Authority {
	return &Authority{
		external: make(map[[sha256.Size]byte]externalRecord),
		sessions: make(map[[sha256.Size]byte]sessionRecord),
		replays:  make(map[string]time.Time), dpop: identity.NewDPoPVerifier(),
		random: rand.Reader, now: time.Now, newID: uuid.NewV7,
	}
}

func (a *Authority) Ready(context.Context) error {
	if a == nil || a.dpop == nil || a.random == nil || a.now == nil || a.newID == nil {
		return ErrIdentityUnavailable
	}
	return nil
}

func (a *Authority) Issue(slot string, thumbprint [sha256.Size]byte) (ExternalToken, error) {
	if a == nil || !validLocalAgent(slot) || zero(thumbprint[:]) {
		return ExternalToken{}, ErrIdentityUnavailable
	}
	credential, digest, err := a.token()
	if err != nil {
		return ExternalToken{}, ErrIdentityUnavailable
	}
	expiresAt := a.now().UTC().Truncate(time.Millisecond).Add(tokenLifetime)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.external[digest] = externalRecord{slot: slot, thumbprint: thumbprint, expiresAt: expiresAt}
	return ExternalToken{Credential: credential, ExpiresAt: expiresAt}, nil
}

func (a *Authority) Bootstrap(ctx context.Context, material httpapi.BootstrapAuthentication) (httpapi.IssuedSession, error) {
	if a == nil || ctx == nil {
		return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
	}
	proof, err := a.dpop.Verify(material.Proof(), material.Credential(), material.Method(), material.TargetURI())
	if err != nil {
		return httpapi.IssuedSession{}, httpapi.ErrUnauthenticated
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	externalDigest := sha256.Sum256([]byte(material.Credential()))
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire(now)
	external, ok := a.external[externalDigest]
	if !ok || external.consumed || !external.expiresAt.After(now) || subtle.ConstantTimeCompare(external.thumbprint[:], proof.JWKThumbprint[:]) != 1 || a.replayed(proof, now) {
		return httpapi.IssuedSession{}, httpapi.ErrUnauthenticated
	}
	external.consumed = true
	a.external[externalDigest] = external
	credential, digest, err := a.token()
	participant, idErr := a.newID()
	if err != nil || idErr != nil || participant.Version() != 7 {
		return httpapi.IssuedSession{}, httpapi.ErrAuthenticationUnavailable
	}
	expiresAt := now.Add(tokenLifetime)
	if external.expiresAt.Before(expiresAt) {
		expiresAt = external.expiresAt
	}
	a.sessions[digest] = sessionRecord{
		identity:   httpapi.Identity{TenantID: "tenant:local-preview", PrincipalID: "principal:" + external.slot, ParticipantInstanceID: participant.String(), SessionEpoch: 1},
		thumbprint: proof.JWKThumbprint, expiresAt: expiresAt,
	}
	return httpapi.IssuedSession{SessionToken: credential, ParticipantInstanceID: participant.String(), SessionEpoch: 1, IssuedAt: now, ExpiresAt: expiresAt}, nil
}

func (a *Authority) Authenticate(ctx context.Context, material httpapi.SessionAuthentication) (httpapi.Identity, error) {
	if a == nil || ctx == nil {
		return httpapi.Identity{}, httpapi.ErrAuthenticationUnavailable
	}
	proof, err := a.dpop.Verify(material.Proof(), material.Credential(), material.Method(), material.TargetURI())
	if err != nil {
		return httpapi.Identity{}, httpapi.ErrUnauthenticated
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	digest := sha256.Sum256([]byte(material.Credential()))
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire(now)
	session, ok := a.sessions[digest]
	if !ok || !session.expiresAt.After(now) || subtle.ConstantTimeCompare(session.thumbprint[:], proof.JWKThumbprint[:]) != 1 || a.replayed(proof, now) {
		return httpapi.Identity{}, httpapi.ErrUnauthenticated
	}
	return session.identity, nil
}

func (a *Authority) replayed(proof identity.Proof, now time.Time) bool {
	key := base64.RawURLEncoding.EncodeToString(proof.JWKThumbprint[:]) + ":" + proof.JTI
	if _, exists := a.replays[key]; exists {
		return true
	}
	a.replays[key] = now.Add(time.Minute)
	return false
}

func (a *Authority) expire(now time.Time) {
	for key, record := range a.external {
		if !record.expiresAt.After(now) {
			delete(a.external, key)
		}
	}
	for key, record := range a.sessions {
		if !record.expiresAt.After(now) {
			delete(a.sessions, key)
		}
	}
	for key, expiresAt := range a.replays {
		if !expiresAt.After(now) {
			delete(a.replays, key)
		}
	}
}

func (a *Authority) token() (string, [sha256.Size]byte, error) {
	var raw [32]byte
	if _, err := io.ReadFull(a.random, raw[:]); err != nil {
		return "", [sha256.Size]byte{}, err
	}
	credential := base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	return credential, sha256.Sum256([]byte(credential)), nil
}

func zero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

var _ httpapi.SessionBootstrapper = (*Authority)(nil)
var _ httpapi.Authenticator = (*Authority)(nil)
