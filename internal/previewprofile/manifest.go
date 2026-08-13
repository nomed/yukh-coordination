// Package previewprofile implements only the execution-forbidden RFC-0025
// manifest contract. It starts no process and creates no credential.
package previewprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	canonical "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"gopkg.in/yaml.v3"
)

const Profile = "yukh-coordination/first-usable-preview-v1"

var ErrInvalidManifest = errors.New("preview profile: invalid manifest")

var imageReference = regexp.MustCompile(`^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$`)
var digestValue = regexp.MustCompile(`^sha-256:[0-9a-f]{64}$`)

type Artifact struct {
	Component string `yaml:"component" json:"component"`
	Image     string `yaml:"image" json:"image"`
}

type Domain struct {
	Role    string `yaml:"role" json:"role"`
	Account string `yaml:"account" json:"account"`
	Storage string `yaml:"storage" json:"storage"`
}

type Manifest struct {
	Profile                string     `yaml:"profile" json:"profile"`
	RunID                  string     `yaml:"run_id" json:"run_id"`
	MaximumLifetimeSeconds int        `yaml:"maximum_lifetime_seconds" json:"maximum_lifetime_seconds"`
	Artifacts              []Artifact `yaml:"artifacts" json:"artifacts"`
	Domains                []Domain   `yaml:"domains" json:"domains"`
}

// ParseManifest accepts one closed YAML document and returns its canonical JSON
// digest. Environment interpolation, aliases, custom tags and implicit values
// are rejected rather than interpreted.
func ParseManifest(raw []byte) (*Manifest, string, error) {
	if len(raw) == 0 || len(raw) > 32*1024 || bytes.Contains(raw, []byte("${")) {
		return nil, "", ErrInvalidManifest
	}
	var node yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if decoder.Decode(&node) != nil || len(node.Content) != 1 || forbiddenNode(node.Content[0]) {
		return nil, "", ErrInvalidManifest
	}
	var manifest Manifest
	decoder = yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if decoder.Decode(&manifest) != nil || !valid(manifest) {
		return nil, "", ErrInvalidManifest
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, "", ErrInvalidManifest
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", ErrInvalidManifest
	}
	canonicalJSON, err := canonical.Transform(encoded)
	if err != nil {
		return nil, "", ErrInvalidManifest
	}
	digest := sha256.Sum256(canonicalJSON)
	return &manifest, "sha-256:" + hex.EncodeToString(digest[:]), nil
}

func forbiddenNode(node *yaml.Node) bool {
	if node.Alias != nil || node.Anchor != "" || (node.Tag != "" && !strings.HasPrefix(node.Tag, "!!")) {
		return true
	}
	for _, child := range node.Content {
		if forbiddenNode(child) {
			return true
		}
	}
	return false
}

func valid(m Manifest) bool {
	if m.Profile != Profile || !slug(m.RunID, 63) || m.MaximumLifetimeSeconds < 1 || m.MaximumLifetimeSeconds > 900 || len(m.Artifacts) != 5 || len(m.Domains) != 3 {
		return false
	}
	components := map[string]bool{"relay": true, "primitives-effect-a": true, "primitives-effect-b": true, "preview-authority": true, "receipt-signer": true}
	seenComponents := map[string]bool{}
	for _, artifact := range m.Artifacts {
		if !components[artifact.Component] || seenComponents[artifact.Component] || !imageReference.MatchString(artifact.Image) {
			return false
		}
		seenComponents[artifact.Component] = true
	}
	for component := range components {
		if !seenComponents[component] {
			return false
		}
	}
	roles, accounts, storage := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, domain := range m.Domains {
		if (domain.Role != "relay" && domain.Role != "effect-a" && domain.Role != "effect-b") || roles[domain.Role] || accounts[domain.Account] || storage[domain.Storage] || !slug(domain.Account, 32) || !slug(domain.Storage, 32) {
			return false
		}
		roles[domain.Role], accounts[domain.Account], storage[domain.Storage] = true, true, true
	}
	return roles["relay"] && roles["effect-a"] && roles["effect-b"]
}

func slug(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}
