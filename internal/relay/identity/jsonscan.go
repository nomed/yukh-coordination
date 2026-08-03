package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var errInvalid = errors.New("identity: invalid authentication material")
var errUnavailable = errors.New("identity: verification unavailable")

const (
	maxJSONDepth   = 8
	maxJSONMembers = 64
	maxJSONString  = 4096
)

func scanJSONObject(data []byte, maxBytes int) error {
	if len(data) == 0 || len(data) > maxBytes {
		return errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return errInvalid
	}
	if err := scanObject(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalid
	}
	return nil
}

func scanObject(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errInvalid
	}
	seen := make(map[string]struct{})
	folded := make(map[string]struct{})
	members := 0
	for decoder.More() {
		nameToken, err := decoder.Token()
		name, ok := nameToken.(string)
		if err != nil || !ok || len(name) == 0 || len(name) > maxJSONString {
			return errInvalid
		}
		members++
		if members > maxJSONMembers {
			return errInvalid
		}
		lower := strings.ToLower(name)
		if _, exists := seen[name]; exists {
			return errInvalid
		}
		if _, exists := folded[lower]; exists {
			return errInvalid
		}
		seen[name] = struct{}{}
		folded[lower] = struct{}{}
		if err := scanValue(decoder, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return errInvalid
	}
	return nil
}

func scanValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return errInvalid
	}
	switch value := token.(type) {
	case string:
		if len(value) > maxJSONString {
			return errInvalid
		}
	case json.Delim:
		switch value {
		case '{':
			return scanObject(decoder, depth)
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > maxJSONMembers || scanValue(decoder, depth+1) != nil {
					return errInvalid
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errInvalid
			}
		default:
			return errInvalid
		}
	}
	return nil
}
