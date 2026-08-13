package previewprofile

import (
	"strings"
	"testing"
)

const validManifest = `profile: yukh-coordination/first-usable-preview-v1
run_id: qualification-01
maximum_lifetime_seconds: 900
artifacts:
  - component: relay
    image: ghcr.io/nomed/relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  - component: primitives-effect-a
    image: ghcr.io/nomed/primitives@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  - component: primitives-effect-b
    image: ghcr.io/nomed/primitives@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  - component: preview-authority
    image: ghcr.io/nomed/authority@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  - component: receipt-signer
    image: ghcr.io/nomed/signer@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
domains:
  - role: relay
    account: relay-01
    storage: relay-store
  - role: effect-a
    account: effect-a-01
    storage: effect-a-store
  - role: effect-b
    account: effect-b-01
    storage: effect-b-store
`

func TestParseManifestReturnsStableCanonicalDigest(t *testing.T) {
	first, digest, err := ParseManifest([]byte(validManifest))
	if err != nil || first.RunID != "qualification-01" || !strings.HasPrefix(digest, "sha-256:") || len(digest) != 72 {
		t.Fatalf("valid manifest rejected: %v %q", err, digest)
	}
	variant := strings.Replace(validManifest,
		"run_id: qualification-01\nmaximum_lifetime_seconds: 900",
		"maximum_lifetime_seconds: 900\nrun_id: qualification-01", 1)
	_, variantDigest, err := ParseManifest([]byte(variant))
	if err != nil || variantDigest != digest {
		t.Fatalf("canonical digest changed: %v %q", err, variantDigest)
	}
}

func TestParseManifestFailsClosed(t *testing.T) {
	cases := map[string]string{
		"unknown":        validManifest + "unexpected: true\n",
		"environment":    strings.Replace(validManifest, "qualification-01", "${RUN_ID}", 1),
		"movable-tag":    strings.Replace(validManifest, "@sha256:"+strings.Repeat("a", 64), ":latest", 1),
		"shared-account": strings.Replace(validManifest, "account: effect-b-01", "account: effect-a-01", 1),
		"shared-storage": strings.Replace(validManifest, "storage: effect-b-store", "storage: effect-a-store", 1),
		"missing-domain": strings.Replace(validManifest, "  - role: effect-b\n    account: effect-b-01\n    storage: effect-b-store\n", "", 1),
		"alias":          "base: &base x\ncopy: *base\n",
		"second-doc":     validManifest + "---\nprofile: other\n",
		"trailing-junk":  validManifest + "{",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseManifest([]byte(raw)); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
