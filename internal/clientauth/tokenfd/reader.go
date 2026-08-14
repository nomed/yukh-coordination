// Package tokenfd reads one DPoP-bound external token from a caller-owned
// descriptor. It has no provider discovery, signature-verification, or
// credential fallback behavior.
package tokenfd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientauth"
	"golang.org/x/sys/unix"
)

const maximumTokenBytes = 8192

// Reader validates the structural and DPoP-key binding properties needed at
// the workstation boundary. Relay authentication remains authoritative because
// this reader deliberately has no issuer trust material.
type Reader struct {
	now func() time.Time
}

// NewReader constructs a reader for one caller-provided token descriptor.
func NewReader() *Reader {
	return &Reader{now: time.Now}
}

// ReadBoundAccessToken reads descriptor once without closing, seeking, or
// replacing it. The descriptor is caller-owned, including when validation
// fails.
func (r *Reader) ReadBoundAccessToken(ctx context.Context, descriptor *os.File, jwk clientauth.PublicP256JWK) (*clientauth.BoundAccessToken, error) {
	if r == nil || r.now == nil || ctx == nil || ctx.Err() != nil || !validDescriptor(descriptor) {
		return nil, clientauth.ErrExternalToken
	}
	raw, err := io.ReadAll(io.LimitReader(descriptor, maximumTokenBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumTokenBytes || ctx.Err() != nil {
		return nil, clientauth.ErrExternalToken
	}
	token := string(raw)
	expiresAt, thumbprint, ok := parse(token)
	clear(raw)
	if !ok || !expiresAt.After(r.now().UTC()) {
		return nil, clientauth.ErrExternalToken
	}
	expected := jwk.Thumbprint()
	if subtle.ConstantTimeCompare(thumbprint[:], expected[:]) != 1 {
		return nil, clientauth.ErrExternalToken
	}
	bound, err := clientauth.NewBoundAccessToken(token, expiresAt)
	if err != nil {
		return nil, clientauth.ErrExternalToken
	}
	return bound, nil
}

func validDescriptor(descriptor *os.File) bool {
	if descriptor == nil || descriptor.Fd() < 3 {
		return false
	}
	flags, err := unix.FcntlInt(descriptor.Fd(), unix.F_GETFL, 0)
	return err == nil && flags&unix.O_ACCMODE == unix.O_RDONLY
}

func parse(token string) (time.Time, [32]byte, bool) {
	var zero [32]byte
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return time.Time{}, zero, false
	}
	header, ok := decodeJSONObject(parts[0])
	if !ok || !validHeader(header) {
		return time.Time{}, zero, false
	}
	claims, ok := decodeJSONObject(parts[1])
	if !ok {
		return time.Time{}, zero, false
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(parts[2]); err != nil {
		return time.Time{}, zero, false
	}
	expiresAt, ok := parseExpiry(claims["exp"])
	if !ok {
		return time.Time{}, zero, false
	}
	confirmation, ok := decodeRawJSONObject(claims["cnf"])
	if !ok {
		return time.Time{}, zero, false
	}
	thumbprint, ok := parseThumbprint(confirmation["jkt"])
	if !ok {
		return time.Time{}, zero, false
	}
	return expiresAt, thumbprint, true
}

func decodeJSONObject(segment string) (map[string]json.RawMessage, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil || len(raw) == 0 || len(raw) > maximumTokenBytes {
		return nil, false
	}
	defer clear(raw)
	return decodeRawJSONObject(raw)
}

func decodeRawJSONObject(raw []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	values := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, exists := values[name]; exists {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		values[name] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	return values, true
}

func validHeader(header map[string]json.RawMessage) bool {
	raw, exists := header["alg"]
	if !exists {
		return false
	}
	var algorithm string
	return json.Unmarshal(raw, &algorithm) == nil && algorithm != "" && algorithm != "none"
}

func parseExpiry(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || bytes.ContainsAny(raw, ".eE") {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	expiresAt := time.Unix(seconds, 0).UTC()
	if expiresAt.IsZero() || expiresAt.Unix() != seconds {
		return time.Time{}, false
	}
	return expiresAt, true
}

func parseThumbprint(raw json.RawMessage) ([32]byte, bool) {
	var zero [32]byte
	var encoded string
	if len(raw) == 0 || json.Unmarshal(raw, &encoded) != nil || len(encoded) != 43 {
		return zero, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != len(zero) {
		clear(decoded)
		return zero, false
	}
	copy(zero[:], decoded)
	clear(decoded)
	return zero, true
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
