package primitivesstaging

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type Authenticator struct {
	registration *Registration
	replays      *ReplayStore
	now          func() time.Time
}

func NewAuthenticator(registration *Registration, replays *ReplayStore, now func() time.Time) (*Authenticator, error) {
	if registration == nil || replays == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Authenticator{registration: registration, replays: replays, now: now}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, material primitivesauth.RequestAuthentication) (primitivesauth.Identity, error) {
	if a == nil || a.registration == nil || a.replays == nil || a.now == nil {
		return primitivesauth.Identity{}, primitivesauth.ErrTemporarilyUnavailable
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	if !validMillisecond(now) || !now.Before(a.registration.expiresAt) || !a.registration.matchesCredential(material.Credential()) {
		return primitivesauth.Identity{}, primitivesauth.ErrUnauthenticated
	}
	proof, err := verifyDPoP(material.Proof(), material.Credential(), material.Method(), material.TargetURI(), now)
	if err != nil || !a.registration.matchesThumbprint(proof.thumbprint) {
		return primitivesauth.Identity{}, primitivesauth.ErrUnauthenticated
	}
	if err := a.replays.Reserve(ctx, proof.thumbprint, proof.jti, proof.issuedAt, now); err != nil {
		if err == ErrReplay {
			return primitivesauth.Identity{}, primitivesauth.ErrUnauthenticated
		}
		return primitivesauth.Identity{}, primitivesauth.ErrTemporarilyUnavailable
	}
	identity, err := a.registration.Identity()
	if err != nil {
		return primitivesauth.Identity{}, primitivesauth.ErrTemporarilyUnavailable
	}
	return identity, nil
}

func (a *Authenticator) Ready() bool {
	if a == nil || a.registration == nil || a.replays == nil || a.now == nil {
		return false
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	return validMillisecond(now) && now.Before(a.registration.expiresAt) && a.replays.Ready(now)
}

func (a *Authenticator) CredentialExpired() bool {
	if a == nil || a.registration == nil || a.now == nil {
		return false
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	return validMillisecond(now) && !now.Before(a.registration.expiresAt)
}

type verifiedProof struct {
	thumbprint [sha256.Size]byte
	jti        string
	issuedAt   time.Time
}

func verifyDPoP(proof, credential, method, target string, now time.Time) (verifiedProof, error) {
	if proof == "" || len(proof) > 16_384 || credential == "" || !ascii(credential) || method != "POST" || !publicTarget(target) {
		return verifiedProof{}, ErrUnauthenticated
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return verifiedProof{}, ErrUnauthenticated
	}
	headerBytes, headerErr := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	payloadBytes, payloadErr := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if headerErr != nil || payloadErr != nil || len(headerBytes) == 0 || len(headerBytes) > 8_192 || len(payloadBytes) == 0 || len(payloadBytes) > 8_192 || !closedJSONObject(headerBytes) || !closedJSONObject(payloadBytes) {
		return verifiedProof{}, ErrUnauthenticated
	}
	header, err := rawObject(headerBytes, "alg", "jwk", "typ")
	if err != nil || rawText(header["alg"]) != "ES256" || rawText(header["typ"]) != "dpop+jwt" {
		return verifiedProof{}, ErrUnauthenticated
	}
	publicKey, thumbprint, err := parseP256JWK(header["jwk"])
	if err != nil {
		return verifiedProof{}, ErrUnauthenticated
	}
	object, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(object.Signatures) != 1 {
		return verifiedProof{}, ErrUnauthenticated
	}
	verified, err := object.Verify(publicKey)
	if err != nil || subtle.ConstantTimeCompare(verified, payloadBytes) != 1 {
		return verifiedProof{}, ErrUnauthenticated
	}
	claims, err := rawObject(payloadBytes, "ath", "htm", "htu", "iat", "jti")
	if err != nil {
		return verifiedProof{}, ErrUnauthenticated
	}
	jti, htm, htu, ath := rawText(claims["jti"]), rawText(claims["htm"]), rawText(claims["htu"]), rawText(claims["ath"])
	expectedATH := sha256.Sum256([]byte(credential))
	issuedSeconds, issuedErr := rawInteger(claims["iat"])
	issuedAt := time.Unix(issuedSeconds, 0).UTC()
	if !base64urlRange(jti, 16, 128) || !constantEqual(htm, method) || !publicTarget(htu) || !constantEqual(htu, target) || !constantEqual(ath, base64.RawURLEncoding.EncodeToString(expectedATH[:])) || issuedErr != nil || issuedAt.After(now.Add(5*time.Second)) || issuedAt.Before(now.Add(-60*time.Second)) {
		return verifiedProof{}, ErrUnauthenticated
	}
	return verifiedProof{thumbprint: thumbprint, jti: jti, issuedAt: issuedAt}, nil
}

func parseP256JWK(raw json.RawMessage) (*ecdsa.PublicKey, [sha256.Size]byte, error) {
	if !closedJSONObject(raw) {
		return nil, [sha256.Size]byte{}, ErrUnauthenticated
	}
	value, err := rawObject(raw, "crv", "kty", "x", "y")
	if err != nil || rawText(value["crv"]) != "P-256" || rawText(value["kty"]) != "EC" {
		return nil, [sha256.Size]byte{}, ErrUnauthenticated
	}
	xBytes, xErr := base64.RawURLEncoding.Strict().DecodeString(rawText(value["x"]))
	yBytes, yErr := base64.RawURLEncoding.Strict().DecodeString(rawText(value["y"]))
	if xErr != nil || yErr != nil || len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, [sha256.Size]byte{}, ErrUnauthenticated
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, [sha256.Size]byte{}, ErrUnauthenticated
	}
	jwk := jose.JSONWebKey{Key: key}
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil || len(thumbprintBytes) != sha256.Size {
		return nil, [sha256.Size]byte{}, ErrUnauthenticated
	}
	var thumbprint [sha256.Size]byte
	copy(thumbprint[:], thumbprintBytes)
	return key, thumbprint, nil
}

func rawObject(raw []byte, expected ...string) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || len(value) != len(expected) {
		return nil, ErrUnauthenticated
	}
	for _, name := range expected {
		if _, ok := value[name]; !ok {
			return nil, ErrUnauthenticated
		}
	}
	return value, nil
}

func rawText(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) != nil || len(value) > 4096 {
		return ""
	}
	return value
}

func rawInteger(raw json.RawMessage) (int64, error) {
	if !integerPattern.Match(raw) {
		return 0, ErrUnauthenticated
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || value > 9_007_199_254_740_991 {
		return 0, ErrUnauthenticated
	}
	return value, nil
}

func publicTarget(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func ascii(value string) bool {
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func base64urlRange(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func constantEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
