// Package previewprofile defines the pure, execution-forbidden RFC-0025
// contracts. It contains no process, network, credential, lease, or provider
// implementation.
package previewprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const maxSafeInteger = uint64(9_007_199_254_740_991)

var (
	ErrInvalid           = errors.New("preview profile: invalid contract")
	ErrScopeMismatch     = errors.New("preview profile: nonce scope mismatch")
	ErrAuthorityReuse    = errors.New("preview profile: cross-effect authority reuse")
	ErrInvalidTransition = errors.New("preview profile: invalid teardown transition")

	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/@-]{0,255}$`)
	digestPattern     = regexp.MustCompile(`^sha-256:[0-9a-f]{64}$`)
	rawDigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	result, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return result, nil
}

func decodeCanonical(raw []byte, value any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrInvalid
	}
	normalized, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(normalized, raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func derive(domain string, body []byte) string {
	preimage := make([]byte, 0, len(domain)+len(body))
	preimage = append(preimage, domain...)
	preimage = append(preimage, body...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }
func validDigest(value string) bool     { return digestPattern.MatchString(value) }
func validRawDigest(value string) bool  { return rawDigestPattern.MatchString(value) }
func validCommit(value string) bool     { return commitPattern.MatchString(value) }
func validPositive(value uint64) bool   { return value > 0 && value <= maxSafeInteger }

func validTime(value string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return parsed, err == nil && parsed.Format("2006-01-02T15:04:05.000Z") == value
}

func validIdentifiers(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
