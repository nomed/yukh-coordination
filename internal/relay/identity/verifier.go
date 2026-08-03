// Package identity implements the accepted identity-provider profile from
// RFC-0010. This increment contains verification only; it owns no session
// persistence, replay registry, auditor or process configuration.
package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

const maxJWTEncoded = 32_768

var tenantPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,255}$`)

type VerifierConfig struct {
	Issuer   string
	Audience string
	JWKS     JWKSConfig
}

type BootstrapIdentity struct {
	TenantID       string
	PrincipalID    string
	DPoPThumbprint [sha256.Size]byte
	TokenExpiresAt time.Time
	ProofJTI       string
	ProofIssuedAt  time.Time
}

type Verifier struct {
	issuer     string
	audience   string
	algorithms map[jose.SignatureAlgorithm]struct{}
	jwks       *jwksCache
	dpop       *DPoPVerifier
	now        func() time.Time
}

func NewVerifier(ctx context.Context, config VerifierConfig) (*Verifier, error) {
	return newVerifier(ctx, config, time.Now)
}

func newVerifier(ctx context.Context, config VerifierConfig, now func() time.Time) (*Verifier, error) {
	if ctx == nil || now == nil || !validConfiguredURI(config.Issuer) || !validConfiguredURI(config.Audience) {
		return nil, errUnavailable
	}
	cache, err := newJWKSCache(ctx, config.JWKS, now)
	if err != nil {
		return nil, err
	}
	algorithms := make(map[jose.SignatureAlgorithm]struct{}, len(config.JWKS.Algorithms))
	for _, algorithm := range config.JWKS.Algorithms {
		algorithms[algorithm] = struct{}{}
	}
	dpop := NewDPoPVerifier()
	dpop.now = now
	return &Verifier{issuer: config.Issuer, audience: config.Audience, algorithms: algorithms, jwks: cache, dpop: dpop, now: now}, nil
}

func (v *Verifier) Close() {
	if v != nil && v.jwks != nil {
		v.jwks.close()
	}
}

func (v *Verifier) VerifyBootstrap(ctx context.Context, token, proof, method, targetURI string) (BootstrapIdentity, error) {
	if v == nil || ctx == nil {
		return BootstrapIdentity{}, errUnavailable
	}
	verifiedProof, err := v.dpop.Verify(proof, token, method, targetURI)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	external, err := v.verifyExternalToken(ctx, token)
	if err != nil {
		return BootstrapIdentity{}, err
	}
	if subtle.ConstantTimeCompare(verifiedProof.JWKThumbprint[:], external.thumbprint[:]) != 1 {
		return BootstrapIdentity{}, errInvalid
	}
	return BootstrapIdentity{
		TenantID: external.tenantID, PrincipalID: external.principalID, DPoPThumbprint: verifiedProof.JWKThumbprint,
		TokenExpiresAt: external.expiresAt, ProofJTI: verifiedProof.JTI, ProofIssuedAt: verifiedProof.IssuedAt,
	}, nil
}

func (v *Verifier) VerifySessionProof(proof, token, method, targetURI string) (Proof, error) {
	if v == nil {
		return Proof{}, errUnavailable
	}
	return v.dpop.Verify(proof, token, method, targetURI)
}

type externalIdentity struct {
	tenantID    string
	principalID string
	thumbprint  [sha256.Size]byte
	expiresAt   time.Time
}

func (v *Verifier) verifyExternalToken(ctx context.Context, token string) (externalIdentity, error) {
	compact, err := decodeCompact(token, maxJWTEncoded, maxJOSEHeader, maxJOSEPayload)
	if err != nil {
		return externalIdentity{}, err
	}
	header, err := rawObject(compact.header, "alg", "kid", "typ")
	if err != nil {
		return externalIdentity{}, err
	}
	algorithmText, err := rawString(header["alg"], 1, 16)
	algorithm := jose.SignatureAlgorithm(algorithmText)
	if err != nil {
		return externalIdentity{}, err
	}
	if _, ok := v.algorithms[algorithm]; !ok || !allowedJWTAlgorithm(algorithm) {
		return externalIdentity{}, errInvalid
	}
	kid, err := rawString(header["kid"], 1, 128)
	if err != nil || !asciiIdentifier(kid) {
		return externalIdentity{}, errInvalid
	}
	typ, err := rawString(header["typ"], 1, 64)
	if err != nil || (strings.ToLower(typ) != "at+jwt" && strings.ToLower(typ) != "application/at+jwt") {
		return externalIdentity{}, errInvalid
	}
	key, err := v.jwks.key(ctx, kid, algorithm)
	if err != nil {
		return externalIdentity{}, err
	}
	object, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{algorithm})
	if err != nil || len(object.Signatures) != 1 {
		return externalIdentity{}, errInvalid
	}
	verifiedPayload, err := object.Verify(key.Key)
	if err != nil || subtle.ConstantTimeCompare(verifiedPayload, compact.payload) != 1 {
		return externalIdentity{}, errInvalid
	}
	claims, err := rawObject(verifiedPayload, "aud", "client_id", "cnf", "exp", "iat", "iss", "jti", "sub", "tenant_id")
	if err != nil {
		return externalIdentity{}, err
	}
	issuer, err := rawString(claims["iss"], 1, 2048)
	if err != nil || !constantStringEqual(issuer, v.issuer) {
		return externalIdentity{}, errInvalid
	}
	if !validAudience(claims["aud"], v.audience) {
		return externalIdentity{}, errInvalid
	}
	subject, err := rawString(claims["sub"], 1, 1024)
	if err != nil || !safeClaimText(subject) {
		return externalIdentity{}, errInvalid
	}
	clientID, err := rawString(claims["client_id"], 1, 256)
	if err != nil || !safeClaimText(clientID) {
		return externalIdentity{}, errInvalid
	}
	tokenJTI, err := rawString(claims["jti"], 1, 256)
	if err != nil || !safeClaimText(tokenJTI) {
		return externalIdentity{}, errInvalid
	}
	tenantID, err := rawString(claims["tenant_id"], 1, 256)
	if err != nil || !tenantPattern.MatchString(tenantID) {
		return externalIdentity{}, errInvalid
	}
	iat, err := rawUint(claims["iat"])
	if err != nil {
		return externalIdentity{}, err
	}
	exp, err := rawUint(claims["exp"])
	if err != nil {
		return externalIdentity{}, err
	}
	issuedAt := time.Unix(iat, 0).UTC()
	expiresAt := time.Unix(exp, 0).UTC()
	now := v.now().UTC()
	if issuedAt.After(now.Add(30*time.Second)) || issuedAt.Before(now.Add(-5*time.Minute)) || !expiresAt.After(now) || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 15*time.Minute {
		return externalIdentity{}, errInvalid
	}
	thumbprint, err := confirmationThumbprint(claims["cnf"])
	if err != nil {
		return externalIdentity{}, err
	}
	return externalIdentity{tenantID: tenantID, principalID: derivePrincipalID(issuer, subject), thumbprint: thumbprint, expiresAt: expiresAt}, nil
}

func confirmationThumbprint(raw json.RawMessage) ([sha256.Size]byte, error) {
	if err := scanJSONObject(raw, 1024); err != nil {
		return [sha256.Size]byte{}, err
	}
	object, err := rawObject(raw, "jkt")
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := rawString(object["jkt"], 43, 43)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) != sha256.Size {
		return [sha256.Size]byte{}, errInvalid
	}
	var result [sha256.Size]byte
	copy(result[:], value)
	return result, nil
}

func validAudience(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return constantStringEqual(single, expected)
	}
	var values []string
	return json.Unmarshal(raw, &values) == nil && len(values) == 1 && constantStringEqual(values[0], expected)
}

func derivePrincipalID(issuer, subject string) string {
	preimage := make([]byte, 0, len(issuer)+len(subject)+48)
	preimage = append(preimage, "yukh-coordination:principal:v1\n"...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(issuer)))
	preimage = append(preimage, length[:]...)
	preimage = append(preimage, issuer...)
	binary.BigEndian.PutUint32(length[:], uint32(len(subject)))
	preimage = append(preimage, length[:]...)
	preimage = append(preimage, subject...)
	digest := sha256.Sum256(preimage)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func safeClaimText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validConfiguredURI(value string) bool {
	return len(value) <= 2048 && validPublicURI(value)
}
