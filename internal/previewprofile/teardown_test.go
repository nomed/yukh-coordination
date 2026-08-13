package previewprofile

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTeardownCompletesInFixedOrder(t *testing.T) {
	var calls []string
	call := func(name string) func(context.Context) error {
		return func(context.Context) error { calls = append(calls, name); return nil }
	}
	digest := "sha-256:" + strings.Repeat("a", 64)
	controller, err := NewTeardown(digest, TeardownPorts{
		CloseAdmission:    call("close-admission"),
		DrainInflight:     call("drain-inflight"),
		FreezeEvidence:    func(context.Context) (string, error) { calls = append(calls, "freeze-evidence"); return digest, nil },
		RevokeCredentials: call("revoke-credentials"),
		StopProcesses:     call("stop-processes"),
		RemoveStorage:     call("remove-storage"),
		RemoveNetwork:     call("remove-network"),
		VerifyAbsence:     call("verify-absence"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Run(context.Background())
	if err != nil || controller.State() != StateCompleted {
		t.Fatalf("teardown failed: %v state=%s", err, controller.State())
	}
	want := []string{"close-admission", "drain-inflight", "freeze-evidence", "revoke-credentials", "stop-processes", "remove-storage", "remove-network", "verify-absence"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
	var receipt TeardownReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "complete" || len(receipt.Steps) != 8 || receipt.EvidenceDigest != digest {
		t.Fatalf("receipt=%s", raw)
	}
	if _, err := controller.Run(context.Background()); !errors.Is(err, ErrTeardownAlreadyRun) {
		t.Fatalf("second run error=%v", err)
	}
}

func TestTeardownQuarantinesAtFirstFailure(t *testing.T) {
	var calls []string
	call := func(name string, failure bool) func(context.Context) error {
		return func(context.Context) error {
			calls = append(calls, name)
			if failure {
				return errors.New("private failure detail")
			}
			return nil
		}
	}
	digest := "sha-256:" + strings.Repeat("b", 64)
	controller, err := NewTeardown(digest, TeardownPorts{
		CloseAdmission:    call("close-admission", false),
		DrainInflight:     call("drain-inflight", false),
		FreezeEvidence:    func(context.Context) (string, error) { calls = append(calls, "freeze-evidence"); return digest, nil },
		RevokeCredentials: call("revoke-credentials", false),
		StopProcesses:     call("stop-processes", true),
		RemoveStorage:     call("remove-storage", false),
		RemoveNetwork:     call("remove-network", false),
		VerifyAbsence:     call("verify-absence", false),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := controller.Run(context.Background())
	if err == nil || controller.State() != StateIncomplete {
		t.Fatalf("failure not quarantined: %v state=%s", err, controller.State())
	}
	if strings.Contains(string(raw), "private failure detail") {
		t.Fatalf("receipt leaked cause: %s", raw)
	}
	want := []string{"close-admission", "drain-inflight", "freeze-evidence", "revoke-credentials", "stop-processes"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup continued after ambiguity: %v", calls)
	}
	var receipt TeardownReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "teardown_incomplete" || receipt.Steps[len(receipt.Steps)-1].Outcome != "failed" {
		t.Fatalf("receipt=%s", raw)
	}
}

func TestNewTeardownRejectsIncompletePortsAndDigest(t *testing.T) {
	if _, err := NewTeardown("sha-256:bad", TeardownPorts{}); err == nil {
		t.Fatal("invalid teardown accepted")
	}
}
