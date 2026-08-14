package clientcli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/nomed/yukh-coordination/internal/clientauth"
)

type bootstrapOperationStub struct {
	bootstrapCalls int
	closeCalls     int
	bootstrapErr   error
	closeErr       error
}

func (s *bootstrapOperationStub) Bootstrap(context.Context) error {
	s.bootstrapCalls++
	return s.bootstrapErr
}

func (s *bootstrapOperationStub) Close() error {
	s.closeCalls++
	return s.closeErr
}

func TestBootstrapRunnerRejectsInvalidArgumentsBeforeComposition(t *testing.T) {
	calls := 0
	runner := BootstrapRunner{Open: func(context.Context, string, int, int) (BootstrapOperation, error) {
		calls++
		return &bootstrapOperationStub{}, nil
	}}
	cases := [][]string{
		nil,
		{"--config", "relative", "--token-fd", "3", "--bus-fd", "4"},
		{"--config", "/private/config", "--token-fd", "03", "--bus-fd", "4"},
		{"--config", "/private/config", "--token-fd", "3", "--bus-fd", "3"},
		{"--config", "/private/config", "--token-fd", "0", "--bus-fd", "4"},
		{"--config", "/private/config", "--token-fd", "3", "--bus-fd", "4", "--bus-fd", "5"},
	}

	for _, args := range cases {
		t.Run("invalid", func(t *testing.T) {
			var output bytes.Buffer
			if status := runner.Run(context.Background(), args, &output); status != 2 || !bytes.Equal(output.Bytes(), []byte("{\"schema\":1,\"status\":\"error\",\"command\":\"session bootstrap\",\"code\":\"YKC-INPUT-001\"}\n")) {
				t.Fatalf("status=%d output=%s", status, output.Bytes())
			}
		})
	}
	if calls != 0 {
		t.Fatalf("composition opened %d times", calls)
	}
}

func TestBootstrapRunnerAllowsProfileWithoutBusDescriptor(t *testing.T) {
	operation := &bootstrapOperationStub{}
	runner := BootstrapRunner{Open: func(_ context.Context, config string, tokenFD, busFD int) (BootstrapOperation, error) {
		if config != "/private/macos.json" || tokenFD != 4 || busFD != 0 {
			t.Fatalf("unexpected inputs: %q %d %d", config, tokenFD, busFD)
		}
		return operation, nil
	}}
	var output bytes.Buffer
	status := runner.Run(context.Background(), []string{"--config", "/private/macos.json", "--token-fd", "4"}, &output)
	if status != 0 || operation.bootstrapCalls != 1 || operation.closeCalls != 1 {
		t.Fatalf("status=%d bootstrap=%d close=%d", status, operation.bootstrapCalls, operation.closeCalls)
	}
}

func TestBootstrapRunnerEmitsStableSuccessAndClosesComposition(t *testing.T) {
	operation := &bootstrapOperationStub{}
	runner := BootstrapRunner{Open: func(_ context.Context, config string, tokenFD, busFD int) (BootstrapOperation, error) {
		if config != "/private/config.json" || tokenFD != 4 || busFD != 5 {
			t.Fatalf("unexpected descriptors: %q %d %d", config, tokenFD, busFD)
		}
		return operation, nil
	}}
	var output bytes.Buffer
	status := runner.Run(context.Background(), []string{"--config", "/private/config.json", "--token-fd", "4", "--bus-fd", "5"}, &output)
	if status != 0 || operation.bootstrapCalls != 1 || operation.closeCalls != 1 ||
		!bytes.Equal(output.Bytes(), []byte("{\"schema\":1,\"status\":\"ok\",\"command\":\"session bootstrap\",\"result\":{\"outcome\":\"bootstrapped\"}}\n")) {
		t.Fatalf("status=%d bootstrap=%d close=%d output=%s", status, operation.bootstrapCalls, operation.closeCalls, output.Bytes())
	}
}

func TestBootstrapRunnerMapsSanitizedFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		open   error
		run    error
		status int
		code   string
	}{
		{"invalid-config", clientauth.ErrInvalidCredential, nil, 2, "YKC-INPUT-001"},
		{"token", nil, clientauth.ErrExternalToken, 3, "YKC-AUTH-001"},
		{"store", nil, clientauth.ErrCredentialStore, 8, "YKC-CUSTODY-001"},
		{"transport", nil, errors.New("private transport failure"), 7, "YKC-UNAVAILABLE-001"},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := &bootstrapOperationStub{bootstrapErr: test.run}
			runner := BootstrapRunner{Open: func(context.Context, string, int, int) (BootstrapOperation, error) {
				if test.open != nil {
					return nil, test.open
				}
				return operation, nil
			}}
			var output bytes.Buffer
			status := runner.Run(context.Background(), []string{"--config", "/private/config.json", "--token-fd", "4", "--bus-fd", "5"}, &output)
			if status != test.status || !bytes.Contains(output.Bytes(), []byte(test.code)) || bytes.Contains(output.Bytes(), []byte("private")) {
				t.Fatalf("status=%d output=%s", status, output.Bytes())
			}
		})
	}
}

func TestCommandRoutesBootstrapWithoutReadingStandardInput(t *testing.T) {
	operation := &bootstrapOperationStub{}
	command := Command{Bootstrap: BootstrapRunner{Open: func(context.Context, string, int, int) (BootstrapOperation, error) {
		return operation, nil
	}}}
	var output bytes.Buffer
	status := command.Run(context.Background(), []string{"session", "bootstrap", "--config", "/private/config.json", "--token-fd", "4", "--bus-fd", "5"}, failingReader{}, &output)
	if status != 0 || operation.bootstrapCalls != 1 || bytes.Contains(output.Bytes(), []byte("standard input")) {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("standard input was read")
}
