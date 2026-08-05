package main

import (
	"io"
	"os"
	"path/filepath"

	"github.com/nomed/yukh-coordination/internal/primitivesceremony"
)

const failure = "offline ceremony unavailable\n"

func main() {
	if execute(os.Args[1:]) == nil {
		return
	}
	_, _ = io.WriteString(os.Stderr, failure)
	os.Exit(1)
}

func execute(arguments []string) error {
	if len(arguments) != 2 || !filepath.IsAbs(arguments[1]) {
		return primitivesceremony.ErrInvalid
	}
	if arguments[0] == "verify" {
		return primitivesceremony.Verify(arguments[1])
	}
	if !filepath.IsAbs(arguments[0]) {
		return primitivesceremony.ErrInvalid
	}
	raw, err := os.ReadFile(arguments[0])
	if err != nil {
		return primitivesceremony.ErrInvalid
	}
	return (primitivesceremony.Generator{}).Generate(raw, arguments[1])
}
