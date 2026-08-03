package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nomed/yukh-coordination/internal/primitivesbootstrap"
	"golang.org/x/sys/unix"
)

func TestExecuteUsesOneAbsoluteConfigAndFixedDescriptor(t *testing.T) {
	captured := false
	capture := func(value int) (*primitivesbootstrap.CredentialDescriptor, error) {
		captured = true
		if value != natsCredentialDescriptor {
			t.Fatal("descriptor slot drifted")
		}
		fd, err := unix.MemfdCreate("bootstrap-main-test", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		return primitivesbootstrap.CaptureCredentialDescriptor(fd)
	}
	run := func(_ context.Context, path string, _ *primitivesbootstrap.CredentialDescriptor, revision string) (primitivesbootstrap.Receipt, error) {
		if path != "/private/bootstrap.json" || revision != buildRevision {
			t.Fatal("executable contract drifted")
		}
		return primitivesbootstrap.Receipt{}, nil
	}
	if _, err := execute(context.Background(), []string{"bootstrap", "/private/bootstrap.json"}, capture, run); err != nil || !captured {
		t.Fatalf("execute=%v captured=%v", err, captured)
	}
	for _, args := range [][]string{{"bootstrap"}, {"bootstrap", "relative.json"}, {"bootstrap", "/one", "/two"}} {
		captured = false
		if _, err := execute(context.Background(), args, capture, run); !errors.Is(err, primitivesbootstrap.ErrInvalid) || captured {
			t.Fatalf("args=%v err=%v captured=%v", args, err, captured)
		}
	}
}

func TestExecuteMapsCaptureAndRunFailure(t *testing.T) {
	private := errors.New("private credential and endpoint detail")
	if _, err := execute(context.Background(), []string{"bootstrap", "/private/bootstrap.json"}, func(int) (*primitivesbootstrap.CredentialDescriptor, error) { return nil, private }, func(context.Context, string, *primitivesbootstrap.CredentialDescriptor, string) (primitivesbootstrap.Receipt, error) {
		return primitivesbootstrap.Receipt{}, nil
	}); !errors.Is(err, primitivesbootstrap.ErrUnavailable) || strings.Contains(err.Error(), "credential") {
		t.Fatalf("capture failure=%v", err)
	}
	capture := func(int) (*primitivesbootstrap.CredentialDescriptor, error) {
		fd, err := unix.MemfdCreate("bootstrap-main-failure", unix.MFD_CLOEXEC)
		if err != nil {
			return nil, err
		}
		return primitivesbootstrap.CaptureCredentialDescriptor(fd)
	}
	if _, err := execute(context.Background(), []string{"bootstrap", "/private/bootstrap.json"}, capture, func(context.Context, string, *primitivesbootstrap.CredentialDescriptor, string) (primitivesbootstrap.Receipt, error) {
		return primitivesbootstrap.Receipt{}, private
	}); !errors.Is(err, primitivesbootstrap.ErrUnavailable) || strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("run failure=%v", err)
	}
}
