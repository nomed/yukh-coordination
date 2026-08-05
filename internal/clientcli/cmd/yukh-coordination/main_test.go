package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/nomed/yukh-coordination/internal/clientcli"
)

func TestExecutableBoundary(t *testing.T) {
	var output bytes.Buffer
	if status := (clientcli.Command{}).Run(context.Background(), []string{"version"}, bytes.NewReader(nil), &output); status != 0 {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}
