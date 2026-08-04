package protocol_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func TestEventFixturesMatchPublishedConformance(t *testing.T) {
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := repositoryRoot(t)
	indexBytes, err := os.ReadFile(filepath.Join(root, "conformance/fixtures/index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Path   string `json:"path"`
		Schema string `json:"schema"`
		Valid  bool   `json:"valid"`
	}
	if err := json.Unmarshal(indexBytes, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		if fixture.Schema != "schema/envelope-0.1.schema.json" {
			continue
		}
		t.Run(filepath.Base(fixture.Path), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, fixture.Path))
			if err != nil {
				t.Fatal(err)
			}
			canonical, canonicalErr := protocol.Canonicalize(raw)
			if canonicalErr == nil {
				_, canonicalErr = validator.Validate(canonical)
			}
			if got := canonicalErr == nil; got != fixture.Valid {
				t.Fatalf("valid=%v, want %v: %v", got, fixture.Valid, canonicalErr)
			}
		})
	}
}

func TestAdmissionRejectsNonCanonicalDuplicateNumericAndDeepInput(t *testing.T) {
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "conformance/fixtures/positive/event-join.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Validate(raw); err == nil {
		t.Fatal("pretty-printed input was accepted")
	}
	for _, invalid := range [][]byte{
		[]byte(`{"id":"one","id":"two"}`),
		[]byte(`{"value":1}`),
		[]byte(strings.Repeat(`{"x":`, 17) + `true` + strings.Repeat(`}`, 17)),
	} {
		if _, err := validator.Validate(invalid); err == nil {
			t.Fatalf("invalid input accepted: %s", invalid)
		}
	}
}

func TestChannelMetadataExposesImmutableRetentionBinding(t *testing.T) {
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "conformance/canonical/channel.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := validator.ValidateChannelMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.RetentionPolicyDigest != "sha-256:"+strings.Repeat("1", 64) || metadata.RetentionEpoch != 0 || metadata.CreatedAt != "2026-08-02T16:00:00.000Z" {
		t.Fatalf("retention binding not exposed exactly: %#v", metadata)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}
