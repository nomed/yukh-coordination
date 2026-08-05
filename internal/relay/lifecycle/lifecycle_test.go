package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nomed/yukh-coordination/internal/relay"
)

type vectors struct {
	Policy          string `json:"policy"`
	PolicyDigest    string `json:"policy_digest"`
	Intent          string `json:"intent"`
	IntentDigest    string `json:"intent_digest"`
	Marker          string `json:"marker"`
	MarkerDigest    string `json:"marker_digest"`
	ReceiptPreimage string `json:"receipt_preimage"`
}

func TestCanonicalLifecycleVectors(t *testing.T) {
	fixture := readVectors(t)
	policy, intent, marker, receipt := fixtureValues(fixture)

	policyBytes, err := CanonicalPolicy(policy)
	if err != nil || string(policyBytes) != fixture.Policy {
		t.Fatalf("policy = %q, %v", policyBytes, err)
	}
	if digest, err := PolicyDigest(policy); err != nil || digest != fixture.PolicyDigest {
		t.Fatalf("policy digest = %q, %v", digest, err)
	}
	intentBytes, intentDigest, err := CanonicalIntent(intent)
	if err != nil || string(intentBytes) != fixture.Intent || intentDigest != fixture.IntentDigest {
		t.Fatalf("intent = %q, %q, %v", intentBytes, intentDigest, err)
	}
	markerBytes, markerDigest, err := CanonicalMarker(marker)
	if err != nil || string(markerBytes) != fixture.Marker || markerDigest != fixture.MarkerDigest {
		t.Fatalf("marker = %q, %q, %v", markerBytes, markerDigest, err)
	}
	receiptBytes, signingBytes, err := CanonicalReceiptPreimage(receipt)
	if err != nil || string(receiptBytes) != fixture.ReceiptPreimage {
		t.Fatalf("receipt = %q, %v", receiptBytes, err)
	}
	if !bytes.Equal(signingBytes, append([]byte(receiptSignDomain), receiptBytes...)) {
		t.Fatal("receipt signing domain is not exact")
	}
	for _, value := range [][]byte{policyBytes, intentBytes, markerBytes, receiptBytes} {
		if err := ValidateCanonical(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPolicyRejectsMissingDefaultInfiniteAndDigestReplacement(t *testing.T) {
	fixture := readVectors(t)
	policy, _, _, _ := fixtureValues(fixture)
	invalid := []Policy{
		{},
		func() Policy { value := policy; value.ActiveRetentionMillis = 0; return value }(),
		func() Policy { value := policy; value.ActiveRetentionMillis = MaxSafeInteger + 1; return value }(),
		func() Policy { value := policy; value.PolicyEpoch = 0; return value }(),
		func() Policy { value := policy; value.ExportMode = "inherited"; return value }(),
		func() Policy { value := policy; value.RedactionAuthorityRoleID = "*"; return value }(),
		func() Policy {
			value := policy
			value.PolicyDigest = "sha-256:" + strings.Repeat("f", 64)
			return value
		}(),
	}
	for index, value := range invalid {
		if err := ValidatePolicy(value); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("invalid policy %d accepted: %v", index, err)
		}
	}
}

func TestPolicySuccessorRejectsEpochRollback(t *testing.T) {
	fixture := readVectors(t)
	current, _, _, _ := fixtureValues(fixture)
	next := current
	next.PolicyID = "policy-beta"
	next.PolicyEpoch = 2
	next.ActivatedAt = "2026-08-04T07:00:00.000Z"
	next.PolicyDigest, _ = PolicyDigest(next)
	if err := ValidatePolicySuccessor(current, next); err != nil {
		t.Fatalf("valid successor rejected: %v", err)
	}
	rollback := next
	rollback.PolicyEpoch = current.PolicyEpoch
	rollback.PolicyDigest, _ = PolicyDigest(rollback)
	if err := ValidatePolicySuccessor(current, rollback); !errors.Is(err, ErrConflict) {
		t.Fatalf("policy rollback = %v", err)
	}
}

func TestIntentRejectsBroadeningAndMalformedTargets(t *testing.T) {
	fixture := readVectors(t)
	_, intent, _, _ := fixtureValues(fixture)
	invalid := []Intent{
		func() Intent { value := intent; value.OperationID = "not-v7"; return value }(),
		func() Intent { value := intent; value.Target.Sequences = []uint64{4, 2}; return value }(),
		func() Intent { value := intent; value.Target.Sequences = []uint64{2, 2}; return value }(),
		func() Intent { value := intent; value.Target = Target{Kind: TargetTranscript}; return value }(),
		func() Intent {
			value := intent
			value.ExpectedBackupDeletionWindows = value.ExpectedBackupDeletionWindows[:2]
			return value
		}(),
		func() Intent {
			value := intent
			value.ExpectedBackupDeletionWindows[0].Deadline = value.RequestedAt
			return value
		}(),
	}
	for index, value := range invalid {
		if err := ValidateIntent(value); !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("invalid intent %d accepted: %v", index, err)
		}
	}
}

func TestExactRetryAcceptsOnlyTheOriginalCanonicalIntent(t *testing.T) {
	fixture := readVectors(t)
	_, intent, _, _ := fixtureValues(fixture)
	if err := ValidateRetry(intent, intent); err != nil {
		t.Fatalf("exact retry rejected: %v", err)
	}
	changed := intent
	changed.Target.Sequences = []uint64{2, 4, 6}
	if err := ValidateRetry(intent, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("broadened retry = %v", err)
	}
	replacement := intent
	replacement.OperationID = "0198cf64-cc00-7000-8000-000000000009"
	if err := ValidateRetry(intent, replacement); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement retry = %v", err)
	}
}

func TestEpochZeroAndClosedAuditVocabulary(t *testing.T) {
	fixture := readVectors(t)
	_, intent, _, _ := fixtureValues(fixture)
	intent.Transcript.TranscriptEpoch = 0
	if err := ValidateIntent(intent); err != nil {
		t.Fatalf("existing protocol epoch zero rejected: %v", err)
	}
	for _, reason := range []AuditReason{AuditPolicyActivated, AuditReserved, AuditExportVerified, AuditMarkerPersisted, AuditReceiptSigned, AuditPayloadRemoved, AuditBackupRecorded, AuditCompleted, AuditDeadlineMissed, AuditClockFenced, AuditRestoreVerified, AuditIncidentRecorded} {
		if !ValidAuditReason(reason) {
			t.Fatalf("closed audit reason rejected: %s", reason)
		}
	}
	if ValidAuditReason("provider_error: private/path") {
		t.Fatal("open provider detail accepted as audit reason")
	}
}

func TestTypedAdministrativeRequestsEnforceCrossBindings(t *testing.T) {
	fixture := readVectors(t)
	_, intent, _, _ := fixtureValues(fixture)
	reference := OperationReference{OperationID: intent.OperationID, IntentDigest: fixture.IntentDigest}
	if ValidateOperationReference(reference) != nil || ValidateDueQuery(DueQuery{WallTime: intent.RequestedAt, Limit: 100}) != nil {
		t.Fatal("valid administrative reference rejected")
	}
	if ValidateExportEvidence(ExportEvidence{OperationID: reference.OperationID, IntentDigest: reference.IntentDigest, ManifestDigest: fixture.MarkerDigest, CustodyReceiptDigest: fixture.PolicyDigest}) != nil {
		t.Fatal("valid export evidence rejected")
	}
	persistence := MarkerPersistence{OperationID: reference.OperationID, IntentDigest: reference.IntentDigest, CanonicalMarker: []byte(fixture.Marker), CanonicalPreimage: []byte(fixture.ReceiptPreimage)}
	if err := ValidateMarkerPersistence(persistence); err != nil {
		t.Fatalf("valid marker persistence rejected: %v", err)
	}
	attachment := SignatureAttachment{OperationID: reference.OperationID, IntentDigest: reference.IntentDigest, ReceiptPreimage: []byte(fixture.ReceiptPreimage), Signature: bytes.Repeat([]byte{1}, 64)}
	if err := ValidateSignatureAttachment(attachment); err != nil {
		t.Fatalf("valid signature attachment rejected: %v", err)
	}

	damaged := persistence
	damaged.IntentDigest = "sha-256:" + strings.Repeat("f", 64)
	if err := ValidateMarkerPersistence(damaged); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-bound marker persistence = %v", err)
	}
	attachment.Signature = attachment.Signature[:63]
	if err := ValidateSignatureAttachment(attachment); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("short signature = %v", err)
	}
	if ValidateDueQuery(DueQuery{WallTime: intent.RequestedAt, Limit: 1001}) == nil {
		t.Fatal("unbounded due query accepted")
	}
}

func TestLifecycleTransitionsAndSagaAreClosedAndMonotonic(t *testing.T) {
	for _, transition := range [][2]Lifecycle{{Active, Redacted}, {Active, Deleted}, {Redacted, Deleted}} {
		if !validTransition(transition[0], transition[1]) {
			t.Fatalf("valid transition rejected: %v", transition)
		}
	}
	for _, transition := range [][2]Lifecycle{{Deleted, Active}, {Redacted, Active}, {Deleted, Redacted}, {Active, Active}} {
		if validTransition(transition[0], transition[1]) {
			t.Fatalf("invalid transition accepted: %v", transition)
		}
	}
	states := []SagaState{Reserved, ExportSatisfied, MarkerPersisted, ReceiptSigned, PayloadRemoved, BackupsPending, Completed}
	for index := 0; index < len(states)-1; index++ {
		if !ValidSagaAdvance(states[index], states[index+1]) || ValidSagaAdvance(states[index+1], states[index]) {
			t.Fatalf("invalid saga ordering at %d", index)
		}
	}
	if ValidSagaAdvance(Reserved, MarkerPersisted) || ValidSagaAdvance(Completed, Completed) {
		t.Fatal("skipped or repeated saga transition accepted")
	}
}

func TestAdministrativePortIsSeparateFromRelayStore(t *testing.T) {
	ordinary := reflect.TypeOf((*relay.Store)(nil)).Elem()
	admin := reflect.TypeOf((*TranscriptLifecycleStore)(nil)).Elem()
	if ordinary.AssignableTo(admin) || admin.AssignableTo(ordinary) {
		t.Fatal("ordinary and administrative stores are type-compatible")
	}
	for _, forbidden := range []string{"Reserve", "BindExport", "PersistMarker", "RemovePayload", "RecordBackupReceipt", "Complete", "InspectBackupRecovery"} {
		if _, found := ordinary.MethodByName(forbidden); found {
			t.Fatalf("relay.Store exposes administrative method %s", forbidden)
		}
	}
}

func TestOperationCloneDoesNotShareAdministrativeMaterial(t *testing.T) {
	fixture := readVectors(t)
	_, intent, _, _ := fixtureValues(fixture)
	original := Operation{Intent: intent, IntentDigest: fixture.IntentDigest, State: MarkerPersisted, Marker: []byte(fixture.Marker), Receipt: []byte(fixture.ReceiptPreimage), Signature: bytes.Repeat([]byte{1}, 64)}
	cloned := CloneOperation(original)
	cloned.Intent.Target.Sequences[0] = 99
	cloned.Intent.ExpectedBackupDeletionWindows[0].Deadline = "2026-08-09T00:00:00.000Z"
	cloned.Marker[0], cloned.Receipt[0], cloned.Signature[0] = 'x', 'x', 2
	if original.Intent.Target.Sequences[0] == 99 || original.Intent.ExpectedBackupDeletionWindows[0].Deadline == cloned.Intent.ExpectedBackupDeletionWindows[0].Deadline || original.Marker[0] == 'x' || original.Receipt[0] == 'x' || original.Signature[0] == 2 {
		t.Fatal("operation clone shares mutable administrative material")
	}
}

func TestCanonicalValidationRejectsRepairAndOversize(t *testing.T) {
	fixture := readVectors(t)
	if ValidateCanonical([]byte(" "+fixture.Marker)) == nil || ValidateCanonical([]byte(`{"duplicate":1,"duplicate":2}`)) == nil || ValidateCanonical(bytes.Repeat([]byte("x"), 16_385)) == nil {
		t.Fatal("damaged canonical material accepted")
	}
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", "test-vectors", "transcript-lifecycle-0.1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value vectors
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func fixtureValues(fixture vectors) (Policy, Intent, Marker, ReceiptPreimage) {
	var policy Policy
	var intent Intent
	var marker Marker
	var receipt ReceiptPreimage
	_ = json.Unmarshal([]byte(fixture.Policy), &policy)
	_ = json.Unmarshal([]byte(fixture.Intent), &intent)
	_ = json.Unmarshal([]byte(fixture.Marker), &marker)
	_ = json.Unmarshal([]byte(fixture.ReceiptPreimage), &receipt)
	return policy, intent, marker, receipt
}
