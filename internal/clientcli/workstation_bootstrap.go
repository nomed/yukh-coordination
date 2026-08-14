package clientcli

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"

	"github.com/nomed/yukh-coordination/internal/clientauth"
)

// WorkstationBootstrapOperation is one owned RFC-0014 bootstrap composition.
type WorkstationBootstrapOperation interface {
	Bootstrap(context.Context) error
	Close() error
}

// WorkstationBootstrapOpen constructs one explicitly selected bootstrap composition.
// Implementations must not discover credentials, a D-Bus connection, or a
// network transport from ambient process state.
type WorkstationBootstrapOpen func(context.Context, string, int, int) (WorkstationBootstrapOperation, error)

// WorkstationBootstrapRunner owns the closed session-bootstrap CLI boundary.
type WorkstationBootstrapRunner struct {
	Open WorkstationBootstrapOpen
}

func (r WorkstationBootstrapRunner) Run(ctx context.Context, args []string, stdout io.Writer) int {
	const command = "session bootstrap"
	configPath, tokenFD, busFD, err := parseBootstrap(args)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	if r.Open == nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-UNAVAILABLE-001"}, 7)
	}
	operation, err := r.Open(ctx, configPath, tokenFD, busFD)
	if err != nil {
		return writeBootstrapError(stdout, command, err, true)
	}
	if operation == nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-UNAVAILABLE-001"}, 7)
	}
	defer func() {
		if operation != nil {
			_ = operation.Close()
		}
	}()
	if err := operation.Bootstrap(ctx); err != nil {
		return writeBootstrapError(stdout, command, err, false)
	}
	closeErr := operation.Close()
	operation = nil
	if closeErr != nil {
		return writeBootstrapError(stdout, command, closeErr, false)
	}
	return write(stdout, output{Schema: 1, Status: "ok", Command: command, Result: map[string]string{"outcome": "bootstrapped"}}, 0)
}

func parseBootstrap(args []string) (string, int, int, error) {
	if len(args) != 4 && len(args) != 6 {
		return "", 0, 0, clientauth.ErrInvalidCredential
	}
	values := make(map[string]string, len(args)/2)
	for index := 0; index < len(args); index += 2 {
		key, value := args[index], args[index+1]
		if value == "" {
			return "", 0, 0, clientauth.ErrInvalidCredential
		}
		if _, exists := values[key]; exists {
			return "", 0, 0, clientauth.ErrInvalidCredential
		}
		values[key] = value
	}
	if values["--config"] == "" || values["--token-fd"] == "" ||
		!filepath.IsAbs(values["--config"]) || filepath.Clean(values["--config"]) != values["--config"] {
		return "", 0, 0, clientauth.ErrInvalidCredential
	}
	tokenFD, tokenErr := workstationCanonicalDescriptor(values["--token-fd"])
	if tokenErr != nil {
		return "", 0, 0, clientauth.ErrInvalidCredential
	}
	if values["--bus-fd"] == "" {
		if len(values) != 2 {
			return "", 0, 0, clientauth.ErrInvalidCredential
		}
		return values["--config"], tokenFD, 0, nil
	}
	busFD, busErr := workstationCanonicalDescriptor(values["--bus-fd"])
	if len(values) != 3 || busErr != nil || tokenFD == busFD {
		return "", 0, 0, clientauth.ErrInvalidCredential
	}
	return values["--config"], tokenFD, busFD, nil
}

func workstationCanonicalDescriptor(value string) (int, error) {
	if value == "" || len(value) > 10 || len(value) > 1 && value[0] == '0' {
		return 0, clientauth.ErrInvalidCredential
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, clientauth.ErrInvalidCredential
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 3 {
		return 0, clientauth.ErrInvalidCredential
	}
	return int(parsed), nil
}

func writeBootstrapError(stdout io.Writer, command string, err error, opening bool) int {
	switch {
	case opening && errors.Is(err, clientauth.ErrInvalidCredential):
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	case errors.Is(err, clientauth.ErrExternalToken), errors.Is(err, clientauth.ErrInvalidCredential):
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-AUTH-001"}, 3)
	case errors.Is(err, clientauth.ErrCredentialConflict):
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-CONFLICT-001"}, 5)
	case errors.Is(err, clientauth.ErrCredentialStore), errors.Is(err, clientauth.ErrCredentialMissing),
		errors.Is(err, clientauth.ErrProofSigner), errors.Is(err, clientauth.ErrProofKeyMissing):
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-CUSTODY-001"}, 8)
	default:
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-UNAVAILABLE-001"}, 7)
	}
}
