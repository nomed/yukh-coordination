package clientcli

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type testBootstrapper struct {
	err error
}

func (t testBootstrapper) Bootstrap(context.Context) error {
	return t.err
}

func TestBootstrapRunner(t *testing.T) {
	runner := BootstrapRunner{Bootstrapper: testBootstrapper{}}
	var output bytes.Buffer
	if status := runner.Run(context.Background(), []string{"session", "bootstrap"}, &output); status != 0 {
		t.Errorf("expected 0, got %d", status)
	}

	runner.Bootstrapper = testBootstrapper{err: errors.New("failed")}
	output.Reset()
	if status := runner.Run(context.Background(), []string{"session", "bootstrap"}, &output); status != 7 { // YKC-UNAVAILABLE-001
		t.Errorf("expected 7, got %d", status)
	}
}
