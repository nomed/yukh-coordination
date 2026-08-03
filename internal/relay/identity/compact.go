package identity

import (
	"encoding/base64"
	"strings"
)

type compactJWS struct {
	header  []byte
	payload []byte
}

func decodeCompact(value string, maxEncoded, maxHeader, maxPayload int) (compactJWS, error) {
	if value == "" || len(value) > maxEncoded || !asciiOnly(value) {
		return compactJWS{}, errInvalid
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return compactJWS{}, errInvalid
	}
	header, err := decodeSegment(parts[0], maxHeader)
	if err != nil {
		return compactJWS{}, errInvalid
	}
	payload, err := decodeSegment(parts[1], maxPayload)
	if err != nil {
		return compactJWS{}, errInvalid
	}
	if _, err := decodeSegment(parts[2], maxEncoded); err != nil {
		return compactJWS{}, errInvalid
	}
	if err := scanJSONObject(header, maxHeader); err != nil {
		return compactJWS{}, err
	}
	if err := scanJSONObject(payload, maxPayload); err != nil {
		return compactJWS{}, err
	}
	return compactJWS{header: header, payload: payload}, nil
}

func decodeSegment(value string, maxDecoded int) ([]byte, error) {
	if strings.Contains(value, "=") {
		return nil, errInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maxDecoded {
		return nil, errInvalid
	}
	return decoded, nil
}

func asciiOnly(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}
