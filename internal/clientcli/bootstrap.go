package clientcli

import (
	"context"
	"io"
)

type Bootstrapper interface {
	Bootstrap(context.Context) error
}

type BootstrapRunner struct {
	Bootstrapper Bootstrapper
}

func (r BootstrapRunner) Run(ctx context.Context, args []string, stdout io.Writer) int {
	command := "unknown"
	if len(args) == 2 {
		command = args[0] + " " + args[1]
	}
	if len(args) != 2 || command != "session bootstrap" || r.Bootstrapper == nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	err := r.Bootstrapper.Bootstrap(ctx)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: code(err)}, exit(err))
	}
	return write(stdout, output{Schema: 1, Status: "ok", Command: command}, 0)
}
