package primitivesstaging

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

const registrationProfile = "yukh-coordination/private-primitives-registration/v1"

var requiredActions = [...]primitivesauth.Action{
	primitivesauth.NonceConsume,
	primitivesauth.LeaseAcquire,
	primitivesauth.LeaseInspect,
	primitivesauth.LeaseRenew,
	primitivesauth.LeaseRelease,
}

type registrationJSON struct {
	Actions        []string `json:"actions"`
	DPoPThumbprint string   `json:"dpop_thumbprint"`
	ExpiresAt      string   `json:"expires_at"`
	IssuedAt       string   `json:"issued_at"`
	KeyID          string   `json:"key_id"`
	PrincipalID    string   `json:"principal_id"`
	Profile        string   `json:"profile"`
	TenantID       string   `json:"tenant_id"`
	TokenDigest    string   `json:"token_digest"`
}

type Registration struct {
	tenant, principal, keyID string
	tokenDigest, thumbprint  [sha256.Size]byte
	issuedAt, expiresAt      time.Time
}

func VerifyRegistration(raw, detachedSignature, publicKey []byte, expectedKeyID string, now time.Time) (*Registration, error) {
	if len(raw) == 0 || len(raw) > 8_192 || len(publicKey) != ed25519.PublicKeySize || !closedJSONObject(raw) || !validMillisecond(now) {
		return nil, ErrInvalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(string(detachedSignature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), raw, signature) {
		return nil, ErrInvalid
	}
	var value registrationJSON
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Profile != registrationProfile || !opaque(expectedKeyID, 128) || value.KeyID != expectedKeyID || !opaque(value.KeyID, 128) || !opaque(value.TenantID, 256) || !opaque(value.PrincipalID, 256) || !exactActions(value.Actions) {
		return nil, ErrInvalid
	}
	token, tokenErr := base64.RawURLEncoding.Strict().DecodeString(value.TokenDigest)
	thumbprint, thumbErr := base64.RawURLEncoding.Strict().DecodeString(value.DPoPThumbprint)
	issuedAt, issuedErr := time.Parse("2006-01-02T15:04:05.000Z", value.IssuedAt)
	expiresAt, expiresErr := time.Parse("2006-01-02T15:04:05.000Z", value.ExpiresAt)
	if tokenErr != nil || len(token) != sha256.Size || thumbErr != nil || len(thumbprint) != sha256.Size || issuedErr != nil || expiresErr != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 15*time.Minute || now.Before(issuedAt.Add(-5*time.Second)) || !now.Before(expiresAt) {
		return nil, ErrInvalid
	}
	result := &Registration{tenant: value.TenantID, principal: value.PrincipalID, keyID: value.KeyID, issuedAt: issuedAt, expiresAt: expiresAt}
	copy(result.tokenDigest[:], token)
	copy(result.thumbprint[:], thumbprint)
	return result, nil
}

func (r *Registration) Identity() (primitivesauth.Identity, error) {
	if r == nil {
		return primitivesauth.Identity{}, ErrInvalid
	}
	return primitivesauth.NewIdentity(r.tenant, r.principal)
}
func (r *Registration) ExpiresAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.expiresAt
}
func (*Registration) String() string               { return "Registration{REDACTED}" }
func (*Registration) GoString() string             { return "Registration{REDACTED}" }
func (*Registration) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func (r *Registration) matchesCredential(value string) bool {
	digest := sha256.Sum256(append([]byte("yukh-coordination:staging-token:v1\n"), []byte(value)...))
	return subtle.ConstantTimeCompare(digest[:], r.tokenDigest[:]) == 1
}

func (r *Registration) matchesThumbprint(value [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(value[:], r.thumbprint[:]) == 1
}

// AuthorizeAction binds the exact RFC-0022 action set to the signed identity.
func (r *Registration) AuthorizeAction(_ context.Context, identity primitivesauth.Identity, action primitivesauth.Action) error {
	expected, err := r.Identity()
	if err != nil {
		return primitivesauth.ErrTemporarilyUnavailable
	}
	if !constantEqual(identity.Tenant(), expected.Tenant()) || !constantEqual(identity.Principal(), expected.Principal()) {
		return primitivesauth.ErrAccessDenied
	}
	for _, allowed := range requiredActions {
		if action == allowed {
			return nil
		}
	}
	return primitivesauth.ErrAccessDenied
}

func exactActions(values []string) bool {
	if len(values) != len(requiredActions) {
		return false
	}
	for index, action := range requiredActions {
		if values[index] != string(action) {
			return false
		}
	}
	return true
}

func validMillisecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}

func closedJSONObject(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	if !scanObject(decoder, 1) {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func scanObject(decoder *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	seen, folded := map[string]struct{}{}, map[string]struct{}{}
	count := 0
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || name == "" || len(name) > 4096 {
			return false
		}
		count++
		lower := strings.ToLower(name)
		if count > 64 {
			return false
		}
		if _, exists := seen[name]; exists {
			return false
		}
		if _, exists := folded[lower]; exists {
			return false
		}
		seen[name], folded[lower] = struct{}{}, struct{}{}
		if !scanValue(decoder, depth+1) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && end == json.Delim('}')
}

func scanValue(decoder *json.Decoder, depth int) bool {
	if depth > 8 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case string:
		return len(value) <= 4096
	case json.Delim:
		switch value {
		case '{':
			return scanObject(decoder, depth)
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > 64 || !scanValue(decoder, depth+1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	default:
		return true
	}
}
