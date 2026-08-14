package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/nomed/yukh-coordination/internal/previewruntime"
)

const failure = "yukh coordinator unavailable\n"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if execute(ctx, os.Args) != nil {
		_, _ = io.WriteString(os.Stderr, failure)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string) error {
	if ctx == nil || len(args) != 2 || !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] {
		return previewruntime.ErrIdentityUnavailable
	}
	application, err := previewruntime.OpenApplication(ctx, args[1])
	if err != nil {
		return previewruntime.ErrIdentityUnavailable
	}
	return application.Run(ctx)
}
