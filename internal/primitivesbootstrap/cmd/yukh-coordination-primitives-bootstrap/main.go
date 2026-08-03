package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nomed/yukh-coordination/internal/primitivesbootstrap"
)

const (
	natsCredentialDescriptor = 3
	fixedFailure             = "private primitives bootstrap unavailable\n"
)

var buildRevision = "unrecorded"

type captureFunc func(int) (*primitivesbootstrap.CredentialDescriptor, error)
type runFunc func(context.Context, string, *primitivesbootstrap.CredentialDescriptor, string) (primitivesbootstrap.Receipt, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	receipt, err := execute(ctx, os.Args, primitivesbootstrap.CaptureCredentialDescriptor, primitivesbootstrap.Run)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, fixedFailure)
		os.Exit(1)
	}
	raw, err := receipt.Bytes()
	if err != nil {
		_, _ = io.WriteString(os.Stderr, fixedFailure)
		os.Exit(1)
	}
	if written, err := os.Stdout.Write(raw); err != nil || written != len(raw) {
		_, _ = io.WriteString(os.Stderr, fixedFailure)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, capture captureFunc, run runFunc) (primitivesbootstrap.Receipt, error) {
	if ctx == nil || len(args) != 2 || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] || capture == nil || run == nil {
		return primitivesbootstrap.Receipt{}, primitivesbootstrap.ErrInvalid
	}
	descriptor, err := capture(natsCredentialDescriptor)
	if err != nil {
		return primitivesbootstrap.Receipt{}, primitivesbootstrap.ErrUnavailable
	}
	defer descriptor.Close()
	receipt, err := run(ctx, args[1], descriptor, buildRevision)
	if err != nil {
		return primitivesbootstrap.Receipt{}, primitivesbootstrap.ErrUnavailable
	}
	return receipt, nil
}
