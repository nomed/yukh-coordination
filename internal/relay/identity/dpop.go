package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	maxDPoPEncoded = 16_384
	maxJOSEHeader  = 8_192
	maxJOSEPayload = 32_768
)

type Proof struct {
	JWKThumbprint [sha256.Size]byte
	JTI           string
	IssuedAt      time.Time
}

type DPoPVerifier struct {
	now func() time.Time
}

func NewDPoPVerifier() *DPoPVerifier {
	return &DPoPVerifier{now: time.Now}
}

func (v *DPoPVerifier) Verify(proof, credential, method, targetURI string) (Proof, error) {
	if v == nil || v.now == nil || credential == "" || !asciiOnly(credential) || method == "" || method != strings.ToUpper(method) || !validPublicURI(targetURI) {
		return Proof{}, errInvalid
	}
	compact, err := decodeCompact(proof, maxDPoPEncoded, maxJOSEHeader, maxJOSEPayload)
	if err != nil {
		return Proof{}, err
	}
	header, err := rawObject(compact.header, "alg", "jwk", "typ")
	if err != nil {
		return Proof{}, err
	}
	algorithm, err := rawString(header["alg"], 1, 16)
	if err != nil || algorithm != string(jose.ES256) {
		return Proof{}, errInvalid
	}
	typ, err := rawString(header["typ"], 1, 32)
	if err != nil || typ != "dpop+jwt" {
		return Proof{}, errInvalid
	}
	publicKey, thumbprint, err := parseDPoPPublicKey(header["jwk"])
	if err != nil {
		return Proof{}, err
	}
	object, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(object.Signatures) != 1 {
		return Proof{}, errInvalid
	}
	verifiedPayload, err := object.Verify(publicKey)
	if err != nil || subtle.ConstantTimeCompare(verifiedPayload, compact.payload) != 1 {
		return Proof{}, errInvalid
	}
	claims, err := rawObject(verifiedPayload, "ath", "htm", "htu", "iat", "jti")
	if err != nil {
		return Proof{}, err
	}
	jti, err := rawString(claims["jti"], 16, 128)
	if err != nil || !base64URLText(jti) {
		return Proof{}, errInvalid
	}
	htm, err := rawString(claims["htm"], 1, 16)
	if err != nil || !constantStringEqual(htm, method) {
		return Proof{}, errInvalid
	}
	htu, err := rawString(claims["htu"], 1, 4096)
	if err != nil || !validPublicURI(htu) || !constantStringEqual(htu, targetURI) {
		return Proof{}, errInvalid
	}
	ath, err := rawString(claims["ath"], 43, 43)
	expectedATH := sha256.Sum256([]byte(credential))
	if err != nil || !constantStringEqual(ath, base64.RawURLEncoding.EncodeToString(expectedATH[:])) {
		return Proof{}, errInvalid
	}
	iat, err := rawUint(claims["iat"])
	if err != nil {
		return Proof{}, err
	}
	issuedAt := time.Unix(iat, 0).UTC()
	now := v.now().UTC()
	if issuedAt.After(now.Add(5*time.Second)) || issuedAt.Before(now.Add(-60*time.Second)) {
		return Proof{}, errInvalid
	}
	return Proof{JWKThumbprint: thumbprint, JTI: jti, IssuedAt: issuedAt}, nil
}

func parseDPoPPublicKey(data json.RawMessage) (*ecdsa.PublicKey, [sha256.Size]byte, error) {
	if err := scanJSONObject(data, 2048); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	object, err := rawObject(data, "crv", "kty", "x", "y")
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	kty, err := rawString(object["kty"], 1, 8)
	if err != nil || kty != "EC" {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	curve, err := rawString(object["crv"], 1, 16)
	if err != nil || curve != "P-256" {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	xText, err := rawString(object["x"], 43, 43)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	yText, err := rawString(object["y"], 43, 43)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	xBytes, err := base64.RawURLEncoding.Strict().DecodeString(xText)
	if err != nil || len(xBytes) != 32 {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	yBytes, err := base64.RawURLEncoding.Strict().DecodeString(yText)
	if err != nil || len(yBytes) != 32 {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	jwk := jose.JSONWebKey{Key: publicKey}
	value, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil || len(value) != sha256.Size {
		return nil, [sha256.Size]byte{}, errInvalid
	}
	var thumbprint [sha256.Size]byte
	copy(thumbprint[:], value)
	return publicKey, thumbprint, nil
}

func validPublicURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func base64URLText(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func constantStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
