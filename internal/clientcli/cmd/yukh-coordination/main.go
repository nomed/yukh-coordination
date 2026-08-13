package main

import (
	"context"
	"os"

	"github.com/nomed/yukh-coordination/internal/clientcli"
)

func main() {
	os.Exit(clientcli.Executable{}.Run(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
}
