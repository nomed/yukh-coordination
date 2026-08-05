// Package clientcli defines the RFC-0013 JSON and exit-code boundary.
package clientcli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
)

const Version = "0.1.0-dev"

type ReplayClient interface {
	Replay(context.Context) (coordclient.ReplayResult, error)
}
type OpenClient func(coordclient.Config) (ReplayClient, error)
type Runner struct{ Open OpenClient }

type output struct {
	Schema  int    `json:"schema"`
	Status  string `json:"status"`
	Command string `json:"command"`
	Result  any    `json:"result,omitempty"`
	Code    string `json:"code,omitempty"`
}

func (r Runner) Run(ctx context.Context, args []string, stdout io.Writer) int {
	command, config, work, err := parse(args)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	if command == "version" {
		return write(stdout, output{Schema: 1, Status: "ok", Command: command, Result: map[string]string{"version": Version}}, 0)
	}
	if r.Open == nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	client, err := r.Open(config)
	if err != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: "YKC-INPUT-001"}, 2)
	}
	replay, err := client.Replay(ctx)
	if err != nil && !errors.Is(err, coordclient.ErrIncomplete) {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Code: code(err)}, exit(err))
	}
	if command == "events replay" {
		if err != nil {
			return write(stdout, output{Schema: 1, Status: "error", Command: command, Result: replay, Code: "YKC-TRANSCRIPT-001"}, 6)
		}
		return write(stdout, output{Schema: 1, Status: "ok", Command: command, Result: replay}, 0)
	}
	view, inspectErr := coordclient.Inspect(replay, work)
	if inspectErr != nil {
		return write(stdout, output{Schema: 1, Status: "error", Command: command, Result: view, Code: "YKC-TRANSCRIPT-001"}, 6)
	}
	return write(stdout, output{Schema: 1, Status: "ok", Command: command, Result: view}, 0)
}

func parse(args []string) (string, coordclient.Config, string, error) {
	if len(args) == 1 && args[0] == "version" {
		return "version", coordclient.Config{}, "", nil
	}
	if len(args) < 2 {
		return "unknown", coordclient.Config{}, "", coordclient.ErrInvalidInput
	}
	command := args[0] + " " + args[1]
	if command != "events replay" && command != "work inspect" {
		return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
	}
	values := map[string]string{}
	for i := 2; i < len(args); i += 2 {
		if i+1 >= len(args) || values[args[i]] != "" {
			return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
		}
		values[args[i]] = args[i+1]
	}
	allowed := map[string]bool{"--base-uri": true, "--channel-id": true, "--channel-uri": true, "--transcript-epoch": true, "--limit": true, "--max-records": true, "--work-uri": command == "work inspect"}
	for key := range values {
		if !allowed[key] {
			return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
		}
	}
	epoch, e := canonicalUint(values["--transcript-epoch"])
	if e != nil {
		return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
	}
	parsedLimit, e := canonicalUint(values["--limit"])
	if e != nil || parsedLimit > uint64(^uint(0)>>1) {
		return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
	}
	parsedMax, e := canonicalUint(values["--max-records"])
	if e != nil || parsedMax > uint64(^uint(0)>>1) {
		return command, coordclient.Config{}, "", coordclient.ErrInvalidInput
	}
	limit, max := int(parsedLimit), int(parsedMax)
	config := coordclient.Config{BaseURI: values["--base-uri"], ChannelID: values["--channel-id"], ChannelURI: values["--channel-uri"], TranscriptEpoch: epoch, PageLimit: limit, MaxRecords: max}
	if command == "work inspect" && values["--work-uri"] == "" {
		return command, config, "", coordclient.ErrInvalidInput
	}
	return command, config, values["--work-uri"], nil
}

func canonicalUint(value string) (uint64, error) {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return 0, coordclient.ErrInvalidInput
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, coordclient.ErrInvalidInput
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

func code(err error) string {
	switch {
	case errors.Is(err, coordclient.ErrAuthentication):
		return "YKC-AUTH-001"
	case errors.Is(err, coordclient.ErrAccessDenied):
		return "YKC-ACCESS-001"
	case errors.Is(err, coordclient.ErrIncomplete), errors.Is(err, coordclient.ErrInvalidRecord):
		return "YKC-TRANSCRIPT-001"
	case errors.Is(err, coordclient.ErrConflict):
		return "YKC-CONFLICT-001"
	default:
		return "YKC-UNAVAILABLE-001"
	}
}
func exit(err error) int {
	switch {
	case errors.Is(err, coordclient.ErrAuthentication):
		return 3
	case errors.Is(err, coordclient.ErrAccessDenied):
		return 4
	case errors.Is(err, coordclient.ErrIncomplete), errors.Is(err, coordclient.ErrInvalidRecord):
		return 6
	case errors.Is(err, coordclient.ErrConflict):
		return 5
	default:
		return 7
	}
}
func write(w io.Writer, value output, status int) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 9
	}
	if _, err = w.Write(append(encoded, '\n')); err != nil {
		return 9
	}
	return status
}
