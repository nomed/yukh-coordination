package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestJSONPreScanRejectsAmbiguityAndBounds(t *testing.T) {
	tests := map[string]string{
		"duplicate":      `{"a":1,"a":2}`,
		"case-collision": `{"typ":"a","Typ":"b"}`,
		"nested":         `{"a":{"jkt":"a","jkt":"b"}}`,
		"trailing":       `{"a":1}{"b":2}`,
		"root-array":     `[]`,
		"deep":           strings.Repeat(`{"a":`, maxJSONDepth+1) + `0` + strings.Repeat(`}`, maxJSONDepth+1),
		"long-string":    `{"a":"` + strings.Repeat("x", maxJSONString+1) + `"}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if err := scanJSONObject([]byte(input), len(input)+1); !errors.Is(err, errInvalid) {
				t.Fatalf("ambiguous JSON accepted: %v", err)
			}
		})
	}
}

func FuzzJSONPreScanNeverPanics(f *testing.F) {
	for _, seed := range []string{`{}`, `{"a":1}`, `{"a":{"b":[1,true,null,"x"]}}`, `{"a":1,"a":2}`, string([]byte{0xff, 0x00})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = scanJSONObject([]byte(input), 4096)
	})
}

func FuzzCompactDecoderNeverPanics(f *testing.F) {
	for _, seed := range []string{"a.b.c", "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", "..", strings.Repeat("a", 5000)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = decodeCompact(input, 4096, 1024, 2048)
	})
}
