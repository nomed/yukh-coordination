package previewprofile_test

import (
	"errors"
	"testing"

	"github.com/nomed/yukh-coordination/internal/previewprofile"
)

func TestTeardownTransitionsExhaustive(t *testing.T) {
	states := previewprofile.TeardownStates()
	allowed := map[[2]previewprofile.TeardownState]struct{}{
		{previewprofile.TeardownRequested, previewprofile.TeardownAdmissionClosed}:           {},
		{previewprofile.TeardownAdmissionClosed, previewprofile.TeardownEvidenceFrozen}:      {},
		{previewprofile.TeardownEvidenceFrozen, previewprofile.TeardownCredentialsRevoked}:   {},
		{previewprofile.TeardownCredentialsRevoked, previewprofile.TeardownProcessesStopped}: {},
		{previewprofile.TeardownProcessesStopped, previewprofile.TeardownStorageRemoved}:     {},
		{previewprofile.TeardownStorageRemoved, previewprofile.TeardownAbsenceVerified}:      {},
		{previewprofile.TeardownAbsenceVerified, previewprofile.TeardownCompleted}:           {},
	}
	for _, current := range states {
		for _, next := range states {
			_, shouldAllow := allowed[[2]previewprofile.TeardownState{current, next}]
			err := previewprofile.ValidateTeardownTransition(current, next)
			if shouldAllow != (err == nil) {
				t.Fatalf("transition %s -> %s: got %v", current, next, err)
			}
			if !shouldAllow && !errors.Is(err, previewprofile.ErrInvalidTransition) {
				t.Fatalf("transition %s -> %s did not fail closed", current, next)
			}
		}
	}
	for _, transition := range [][2]previewprofile.TeardownState{
		{"", previewprofile.TeardownRequested},
		{"unknown", previewprofile.TeardownCompleted},
		{previewprofile.TeardownCompleted, "unknown"},
	} {
		if !errors.Is(previewprofile.ValidateTeardownTransition(transition[0], transition[1]), previewprofile.ErrInvalidTransition) {
			t.Fatalf("invalid transition %q -> %q accepted", transition[0], transition[1])
		}
	}
}

func TestTeardownFailuresExhaustive(t *testing.T) {
	for _, state := range previewprofile.TeardownStates() {
		next, err := previewprofile.FailTeardown(state)
		allowed := state != previewprofile.TeardownCompleted && state != previewprofile.TeardownIncomplete
		if allowed && (err != nil || next != previewprofile.TeardownIncomplete) {
			t.Fatalf("failure from %s did not quarantine: %s, %v", state, next, err)
		}
		if !allowed && !errors.Is(err, previewprofile.ErrInvalidTransition) {
			t.Fatalf("terminal failure from %s did not fail closed", state)
		}
	}
	if _, err := previewprofile.FailTeardown("unknown"); !errors.Is(err, previewprofile.ErrInvalidTransition) {
		t.Fatal("failure from unknown state accepted")
	}
}
