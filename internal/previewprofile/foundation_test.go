package previewprofile_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/previewprofile"
	protocolschema "github.com/nomed/yukh-coordination/schema"
)

type effectFixture struct {
	Binding          string `json:"binding"`
	LeaseHolder      string `json:"lease_holder"`
	LeaseResource    string `json:"lease_resource"`
	NonceScope       string `json:"nonce_scope"`
	NonceScopeDigest string `json:"nonce_scope_digest"`
	NonceValue       string `json:"nonce_value"`
	PreLease         string `json:"prelease"`
}

type negativeFixture struct {
	Expected                 string `json:"expected"`
	ExpectedConsumedOutcomes int    `json:"expected_consumed_outcomes"`
	ExpectedServiceCalls     int    `json:"expected_service_calls"`
	Name                     string `json:"name"`
}

type fixture struct {
	Domains        map[string]string `json:"domains"`
	EffectA        effectFixture     `json:"effect_a"`
	EffectB        effectFixture     `json:"effect_b"`
	Negative       []negativeFixture `json:"negative"`
	PublicEvidence string            `json:"public_evidence"`
	RunManifest    string            `json:"run_manifest"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	raw, err := fs.ReadFile(protocolschema.FS, "test-vectors/suite-preview-rfc-0025-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var value fixture
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("invalid RFC-0025 fixture")
	}
	return value
}

func decodeFixture[T any](t *testing.T, raw string) T {
	t.Helper()
	var value T
	if json.Unmarshal([]byte(raw), &value) != nil {
		t.Fatal("invalid fixture value")
	}
	return value
}

func TestRunManifestStrictCanonicalParser(t *testing.T) {
	vectors := loadFixture(t)
	manifest, err := previewprofile.ParseRunManifest([]byte(vectors.RunManifest))
	if err != nil {
		t.Fatalf("canonical manifest rejected: %v", err)
	}
	canonical, err := previewprofile.CanonicalRunManifest(manifest)
	if err != nil || string(canonical) != vectors.RunManifest {
		t.Fatal("manifest canonical bytes changed")
	}

	var object map[string]any
	if json.Unmarshal([]byte(vectors.RunManifest), &object) != nil {
		t.Fatal("invalid manifest object")
	}
	object["credential"] = "forbidden"
	if _, err := previewprofile.ParseRunManifest(canonicalJSON(t, object)); !errors.Is(err, previewprofile.ErrInvalid) {
		t.Fatal("manifest accepted unknown credential")
	}
	delete(object, "credential")
	object["maximum_lifetime_seconds"] = 14401
	if _, err := previewprofile.ParseRunManifest(canonicalJSON(t, object)); !errors.Is(err, previewprofile.ErrInvalid) {
		t.Fatal("manifest accepted lifetime above four hours")
	}
	if _, err := previewprofile.ParseRunManifest(append([]byte(vectors.RunManifest), '\n')); !errors.Is(err, previewprofile.ErrInvalid) {
		t.Fatal("manifest accepted non-canonical bytes")
	}

	duplicate := manifest
	duplicate.Components.EffectBPrimitives.LogicalID = duplicate.Components.EffectAPrimitives.LogicalID
	if previewprofile.ValidateRunManifest(duplicate) == nil {
		t.Fatal("manifest accepted duplicate logical service identity")
	}
}

func TestAuthorityConformanceVectors(t *testing.T) {
	vectors := loadFixture(t)
	aScope := decodeFixture[previewprofile.EffectANonceScope](t, vectors.EffectA.NonceScope)
	aPre := decodeFixture[previewprofile.EffectAPreLease](t, vectors.EffectA.PreLease)
	aBinding := decodeFixture[previewprofile.EffectABinding](t, vectors.EffectA.Binding)
	bScope := decodeFixture[previewprofile.EffectBNonceScope](t, vectors.EffectB.NonceScope)
	bPre := decodeFixture[previewprofile.EffectBPreLease](t, vectors.EffectB.PreLease)
	bBinding := decodeFixture[previewprofile.EffectBBinding](t, vectors.EffectB.Binding)

	assertCanonical := func(name, expected string, operation func() ([]byte, error)) {
		t.Helper()
		actual, err := operation()
		if err != nil || string(actual) != expected {
			t.Fatalf("%s canonical bytes changed: %v", name, err)
		}
	}
	assertCanonical("effect A nonce scope", vectors.EffectA.NonceScope, func() ([]byte, error) {
		return previewprofile.CanonicalEffectANonceScope(aScope)
	})
	assertCanonical("effect A prelease", vectors.EffectA.PreLease, func() ([]byte, error) {
		return previewprofile.CanonicalEffectAPreLease(aPre)
	})
	assertCanonical("effect A binding", vectors.EffectA.Binding, func() ([]byte, error) {
		return previewprofile.CanonicalEffectABinding(aBinding)
	})
	assertCanonical("effect B nonce scope", vectors.EffectB.NonceScope, func() ([]byte, error) {
		return previewprofile.CanonicalEffectBNonceScope(bScope)
	})
	assertCanonical("effect B prelease", vectors.EffectB.PreLease, func() ([]byte, error) {
		return previewprofile.CanonicalEffectBPreLease(bPre)
	})
	assertCanonical("effect B binding", vectors.EffectB.Binding, func() ([]byte, error) {
		return previewprofile.CanonicalEffectBBinding(bBinding)
	})

	actual, err := previewprofile.DeriveEffectANonceScopeDigest(aScope)
	assertDerived(t, vectors.EffectA.NonceScopeDigest, actual, err)
	actual, err = previewprofile.DeriveEffectALeaseResource(aPre)
	assertDerived(t, vectors.EffectA.LeaseResource, actual, err)
	actual, err = previewprofile.DeriveEffectALeaseHolder(aPre)
	assertDerived(t, vectors.EffectA.LeaseHolder, actual, err)
	actual, err = previewprofile.DeriveEffectANonceValue(aBinding)
	assertDerived(t, vectors.EffectA.NonceValue, actual, err)
	actual, err = previewprofile.DeriveEffectBNonceScopeDigest(bScope)
	assertDerived(t, vectors.EffectB.NonceScopeDigest, actual, err)
	actual, err = previewprofile.DeriveEffectBLeaseResource(bPre)
	assertDerived(t, vectors.EffectB.LeaseResource, actual, err)
	actual, err = previewprofile.DeriveEffectBLeaseHolder(bPre)
	assertDerived(t, vectors.EffectB.LeaseHolder, actual, err)
	actual, err = previewprofile.DeriveEffectBNonceValue(bBinding)
	assertDerived(t, vectors.EffectB.NonceValue, actual, err)

	expectedDomains := map[string]string{
		"effect_a_nonce_scope":    previewprofile.EffectANonceScopeDomain,
		"effect_a_lease_resource": previewprofile.EffectALeaseResourceDomain,
		"effect_a_lease_holder":   previewprofile.EffectALeaseHolderDomain,
		"effect_a_nonce_value":    previewprofile.EffectANonceValueDomain,
		"effect_b_nonce_scope":    previewprofile.EffectBNonceScopeDomain,
		"effect_b_lease_resource": previewprofile.EffectBLeaseResourceDomain,
		"effect_b_lease_holder":   previewprofile.EffectBLeaseHolderDomain,
		"effect_b_nonce_value":    previewprofile.EffectBNonceValueDomain,
	}
	for name, expected := range expectedDomains {
		if vectors.Domains[name] != expected {
			t.Fatalf("%s domain changed", name)
		}
	}
	if err := previewprofile.ValidateIndependentEffects(aPre, aBinding, bPre, bBinding); err != nil {
		t.Fatalf("independent effects rejected: %v", err)
	}
	aRequest := previewprofile.NonceRequest{
		Epoch: aBinding.PrimitivesRestoreEpoch, ExpiresAt: aBinding.ApprovalExpiresAt,
		ScopeDigest: vectors.EffectA.NonceScopeDigest, ValueDigest: vectors.EffectA.NonceValue,
	}
	if err := previewprofile.ValidateEffectANonceRequest(aPre, aBinding, aRequest); err != nil {
		t.Fatalf("Effect A nonce request rejected: %v", err)
	}
	bRequest := previewprofile.NonceRequest{
		Epoch: bBinding.PrimitivesRestoreEpoch, ExpiresAt: bBinding.ApprovalExpiresAt,
		ScopeDigest: vectors.EffectB.NonceScopeDigest, ValueDigest: vectors.EffectB.NonceValue,
	}
	if err := previewprofile.ValidateEffectBNonceRequest(bPre, bBinding, bRequest); err != nil {
		t.Fatalf("Effect B nonce request rejected: %v", err)
	}
}

func TestAuthorityNegativeVectors(t *testing.T) {
	vectors := loadFixture(t)
	aPre := decodeFixture[previewprofile.EffectAPreLease](t, vectors.EffectA.PreLease)
	aBinding := decodeFixture[previewprofile.EffectABinding](t, vectors.EffectA.Binding)
	bPre := decodeFixture[previewprofile.EffectBPreLease](t, vectors.EffectB.PreLease)
	bBinding := decodeFixture[previewprofile.EffectBBinding](t, vectors.EffectB.Binding)

	negative := make(map[string]negativeFixture, len(vectors.Negative))
	for _, vector := range vectors.Negative {
		negative[vector.Name] = vector
	}

	t.Run("changed scope keeps approved value", func(t *testing.T) {
		vector := negative["changed_scope_same_value"]
		changed := aPre
		changed.ItemIdentity = "project-item-a-changed"
		scope, err := previewprofile.DeriveEffectANonceScopeDigest(changed.EffectANonceScope)
		if err != nil {
			t.Fatal(err)
		}
		changed.NonceScopeDigest = scope
		request := previewprofile.NonceRequest{
			Epoch:       aBinding.PrimitivesRestoreEpoch,
			ExpiresAt:   aBinding.ApprovalExpiresAt,
			ScopeDigest: scope,
			ValueDigest: vectors.EffectA.NonceValue,
		}
		serviceCalls, consumedOutcomes := 0, 0
		if err := previewprofile.ValidateEffectANonceRequest(changed, aBinding, request); err == nil {
			serviceCalls++
			consumedOutcomes++
		} else if !errors.Is(err, previewprofile.ErrScopeMismatch) {
			t.Fatalf("changed scope returned %v", err)
		}
		if vector.Expected != "scope_mismatch" ||
			serviceCalls != vector.ExpectedServiceCalls ||
			consumedOutcomes != vector.ExpectedConsumedOutcomes {
			t.Fatal("changed scope did not fail before a consume call")
		}
	})

	t.Run("cross effect snapshot reuse", func(t *testing.T) {
		vector := negative["cross_effect_snapshot_reuse"]
		bPre.PreconditionSnapshotIdentity = aPre.PreconditionSnapshotIdentity
		scope, _ := previewprofile.DeriveEffectBNonceScopeDigest(bPre.EffectBNonceScope)
		bPre.NonceScopeDigest = scope
		resource, _ := previewprofile.DeriveEffectBLeaseResource(bPre)
		holder, _ := previewprofile.DeriveEffectBLeaseHolder(bPre)
		bBinding.PreconditionSnapshotIdentity = bPre.PreconditionSnapshotIdentity
		bBinding.NonceScopeDigest = scope
		bBinding.LeaseResourceIdentity = resource
		bBinding.LeaseHolderIdentity = holder
		if vector.Expected != "authority_reuse" ||
			!errors.Is(previewprofile.ValidateIndependentEffects(aPre, aBinding, bPre, bBinding), previewprofile.ErrAuthorityReuse) {
			t.Fatal("cross-effect snapshot reuse was not denied")
		}
	})

	t.Run("cross effect binding reuse", func(t *testing.T) {
		vector := negative["cross_effect_binding_reuse"]
		var substituted previewprofile.EffectBBinding
		_ = json.Unmarshal([]byte(vectors.EffectA.Binding), &substituted)
		if vector.Expected != "invalid_contract" ||
			previewprofile.ValidateEffectBAuthority(bPre, substituted) == nil {
			t.Fatal("Effect A binding was accepted as Effect B authority")
		}
		request := previewprofile.NonceRequest{
			Epoch: bBinding.PrimitivesRestoreEpoch, ExpiresAt: bBinding.ApprovalExpiresAt,
			ScopeDigest: bBinding.NonceScopeDigest, ValueDigest: vectors.EffectA.NonceValue,
		}
		if previewprofile.ValidateEffectBNonceRequest(bPre, bBinding, request) == nil {
			t.Fatal("Effect A nonce value was accepted by Effect B")
		}
	})

	t.Run("restore epoch substitution", func(t *testing.T) {
		vector := negative["restore_epoch_substitution"]
		changed := aBinding
		changed.PrimitivesRestoreEpoch++
		if vector.Expected != "invalid_contract" ||
			previewprofile.ValidateEffectAAuthority(aPre, changed) == nil {
			t.Fatal("restore epoch substitution preserved authority")
		}
	})
}

func assertDerived(t *testing.T, expected string, actual string, err error) {
	t.Helper()
	if err != nil || actual != expected {
		t.Fatalf("derived value changed: got %q, want %q: %v", actual, expected, err)
	}
}

func canonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	result, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCanonicalContractsRejectMissingAndSubstitutedFields(t *testing.T) {
	vectors := loadFixture(t)
	for name, raw := range map[string]string{
		"effect A binding": vectors.EffectA.Binding,
		"effect B binding": vectors.EffectB.Binding,
	} {
		t.Run(name, func(t *testing.T) {
			var object map[string]any
			if json.Unmarshal([]byte(raw), &object) != nil {
				t.Fatal("invalid fixture")
			}
			for field := range object {
				changed := make(map[string]any, len(object)-1)
				for key, value := range object {
					if key != field {
						changed[key] = value
					}
				}
				missing := canonicalJSON(t, changed)
				if strings.Contains(name, "A") {
					var value previewprofile.EffectABinding
					_, err := previewprofile.CanonicalEffectABinding(value)
					if json.Unmarshal(missing, &value) == nil {
						_, err = previewprofile.CanonicalEffectABinding(value)
					}
					if err == nil {
						t.Fatalf("accepted missing %s", field)
					}
				} else {
					var value previewprofile.EffectBBinding
					_, err := previewprofile.CanonicalEffectBBinding(value)
					if json.Unmarshal(missing, &value) == nil {
						_, err = previewprofile.CanonicalEffectBBinding(value)
					}
					if err == nil {
						t.Fatalf("accepted missing %s", field)
					}
				}
			}
		})
	}
}
