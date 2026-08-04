package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/nomed/yukh-coordination/internal/primitivesceremony"
)

const failure = "offline ceremony unavailable\n"

func main() {
	if len(os.Args) == 3 && filepath.IsAbs(os.Args[1]) && filepath.IsAbs(os.Args[2]) {
		raw, err := os.ReadFile(os.Args[1])
		if err == nil {
			err = (primitivesceremony.Generator{}).Generate(raw, os.Args[2])
		}
		if err == nil {
			return
		}
	}
	_, _ = io.WriteString(os.Stderr, failure)
	os.Exit(1)
}
