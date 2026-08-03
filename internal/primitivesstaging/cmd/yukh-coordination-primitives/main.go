package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nomed/yukh-coordination/internal/primitivesstaging"
)

const (
	natsCredentialDescriptor = 3
	capabilityKeyDescriptor  = 4
	fixedFailure             = "private primitives staging unavailable\n"
)

var buildRevision = "yukh-coordination-revision:unrecorded"

type application interface {
	Run(context.Context) error
}

type applicationOpener func(context.Context, string, *primitivesstaging.SecretDescriptors, func() time.Time) (application, error)
type descriptorCapture func(int, int) (*primitivesstaging.SecretDescriptors, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !validBuildRevision(buildRevision) || execute(ctx, os.Args, primitivesstaging.CaptureSecretDescriptors, openApplication) != nil {
		_, _ = io.WriteString(os.Stderr, fixedFailure)
		os.Exit(1)
	}
}

func validBuildRevision(value string) bool {
	const prefix = "yukh-coordination-revision:"
	if len(value) != len(prefix)+40 || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func openApplication(ctx context.Context, path string, descriptors *primitivesstaging.SecretDescriptors, now func() time.Time) (application, error) {
	return primitivesstaging.OpenApplication(ctx, path, descriptors, now)
}

func execute(ctx context.Context, args []string, capture descriptorCapture, open applicationOpener) error {
	if ctx == nil || len(args) != 2 || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] || capture == nil || open == nil {
		return primitivesstaging.ErrInvalid
	}
	descriptors, err := capture(natsCredentialDescriptor, capabilityKeyDescriptor)
	if err != nil {
		return primitivesstaging.ErrUnavailable
	}
	defer descriptors.Close()
	now := func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }
	app, err := open(ctx, args[1], descriptors, now)
	if err != nil {
		return primitivesstaging.ErrUnavailable
	}
	if err := app.Run(ctx); err != nil {
		return primitivesstaging.ErrUnavailable
	}
	return nil
}
