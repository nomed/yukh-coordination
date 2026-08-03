package identity

import (
	"encoding/json"
	"regexp"
	"strconv"
)

var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func rawObject(data []byte, expected ...string) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil || len(result) != len(expected) {
		return nil, errInvalid
	}
	for _, name := range expected {
		if _, ok := result[name]; !ok {
			return nil, errInvalid
		}
	}
	return result, nil
}

func rawString(value json.RawMessage, min, max int) (string, error) {
	var result string
	if err := json.Unmarshal(value, &result); err != nil || len(result) < min || len(result) > max {
		return "", errInvalid
	}
	return result, nil
}

func rawUint(value json.RawMessage) (int64, error) {
	if !integerPattern.Match(value) {
		return 0, errInvalid
	}
	result, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil || result > 9_007_199_254_740_991 {
		return 0, errInvalid
	}
	return result, nil
}
