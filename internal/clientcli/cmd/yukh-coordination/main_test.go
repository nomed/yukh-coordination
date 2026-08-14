package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/nomed/yukh-coordination/internal/clientcli"
)

func TestExecutableBoundary(t *testing.T) {
	var output bytes.Buffer
	if status := (clientcli.Executable{}).Run(context.Background(), []string{"version"}, bytes.NewReader(nil), &output); status != 0 {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}

func TestExecutableFailsClosedWithoutWorkstationDependencies(t *testing.T) {
	var output bytes.Buffer
	status := (clientcli.WorkstationBootstrapRunner{}).Run(context.Background(), []string{"--config", "/private/bootstrap.json", "--token-fd", "4", "--bus-fd", "5"}, &output)
	if status != 7 || !bytes.Contains(output.Bytes(), []byte("YKC-UNAVAILABLE-001")) {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}

func TestExecutableBuildsOnlyExplicitWorkstationBootstrap(t *testing.T) {
	var output bytes.Buffer
	status := command().Run(context.Background(), []string{"session", "bootstrap", "--config", "relative.json", "--token-fd", "4", "--bus-fd", "5"}, bytes.NewReader(nil), &output)
	if status != 2 || !bytes.Contains(output.Bytes(), []byte("YKC-INPUT-001")) {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}
