package main

import (
	"io"
	"os"

	"github.com/nomed/yukh-coordination/internal/primitiveslauncher"
)

const fixedFailure = "private primitives launcher unavailable\n"

func main() {
	process, err := primitiveslauncher.Prepare(os.Args[1:])
	if err == nil {
		err = process.Exec()
	}
	if process != nil {
		process.Close()
	}
	_, _ = io.WriteString(os.Stderr, fixedFailure)
	os.Exit(1)
}
