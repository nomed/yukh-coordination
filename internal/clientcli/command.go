package clientcli

import (
	"context"
	"io"
)

var Commands = []string{
	"session bootstrap", "session join", "session leave",
	"work inspect", "work claim", "work progress", "work release",
	"question ask", "question answer", "review request", "review verdict",
	"handoff offer", "handoff accept", "events replay", "events watch", "version",
}

type Command struct {
	Bootstrap BootstrapRunner
	Read      Runner
	Signals   SignalRunner
}

func (c Command) Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) == 1 && args[0] == "help" {
		return write(stdout, output{Schema: 1, Status: "ok", Command: "help", Result: map[string]any{"commands": Commands, "input": "closed JSON on stdin for mutating commands"}}, 0)
	}
	if len(args) == 1 && args[0] == "version" {
		return c.Read.Run(ctx, args, stdout)
	}
	if len(args) == 2 && args[0]+" "+args[1] == "session bootstrap" {
		return c.Bootstrap.Run(ctx, args, stdout)
	}
	if len(args) == 2 && signalCommand(args[0]+" "+args[1]) {
		return c.Signals.Run(ctx, args, stdin, stdout)
	}
	if len(args) >= 2 && (args[0]+" "+args[1] == "events replay" || args[0]+" "+args[1] == "events watch" || args[0]+" "+args[1] == "work inspect") {
		return c.Read.Run(ctx, args, stdout)
	}
	return write(stdout, output{Schema: 1, Status: "error", Command: "unknown", Code: "YKC-INPUT-001"}, 2)
}
