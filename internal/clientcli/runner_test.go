package clientcli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	coordclient "github.com/nomed/yukh-coordination/internal/client"
)

type replayClient struct {
	result coordclient.ReplayResult
	err    error
}

func (r replayClient) Replay(context.Context) (coordclient.ReplayResult, error) {
	return r.result, r.err
}

func TestRunnerEmitsOneClosedJSONDocument(t *testing.T) {
	runner := Runner{Open: func(config coordclient.Config) (ReplayClient, error) {
		if config.BaseURI != "https://coord.example" {
			t.Fatal(config)
		}
		return replayClient{result: coordclient.ReplayResult{SpecVersion: "0.1", ChannelID: "channel:test", ChannelURI: "https://coord.example/channels/test", TranscriptEpoch: 1, Completeness: "complete", Records: []coordclient.Record{}}}, nil
	}}
	var stdout bytes.Buffer
	status := runner.Run(context.Background(), []string{"events", "replay", "--base-uri", "https://coord.example", "--channel-id", "channel:test", "--channel-uri", "https://coord.example/channels/test", "--transcript-epoch", "1", "--limit", "100", "--max-records", "1000"}, &stdout)
	if status != 0 {
		t.Fatal(status)
	}
	var value map[string]any
	if json.Unmarshal(stdout.Bytes(), &value) != nil || value["status"] != "ok" || bytes.Count(stdout.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("%s", stdout.Bytes())
	}
}

func TestRunnerMapsStableFailureWithoutProviderText(t *testing.T) {
	runner := Runner{Open: func(coordclient.Config) (ReplayClient, error) {
		return replayClient{err: fmt.Errorf("private endpoint: %w", coordclient.ErrAuthentication)}, nil
	}}
	var stdout bytes.Buffer
	status := runner.Run(context.Background(), []string{"events", "replay", "--base-uri", "https://coord.example", "--channel-id", "channel:test", "--channel-uri", "https://coord.example/channels/test", "--transcript-epoch", "1", "--limit", "100", "--max-records", "1000"}, &stdout)
	if status != 3 || bytes.Contains(stdout.Bytes(), []byte("private")) {
		t.Fatalf("%d %s", status, stdout.Bytes())
	}
}

func TestRunnerRejectsUnknownAndIncomplete(t *testing.T) {
	runner := Runner{Open: func(coordclient.Config) (ReplayClient, error) {
		return replayClient{result: coordclient.ReplayResult{Completeness: "incomplete"}, err: coordclient.ErrIncomplete}, nil
	}}
	var stdout bytes.Buffer
	if status := runner.Run(context.Background(), []string{"claim"}, &stdout); status != 2 {
		t.Fatal(status)
	}
	stdout.Reset()
	args := []string{"work", "inspect", "--base-uri", "https://coord.example", "--channel-id", "channel:test", "--channel-uri", "https://coord.example/channels/test", "--transcript-epoch", "1", "--limit", "100", "--max-records", "1000", "--work-uri", "https://example.test/work"}
	if status := runner.Run(context.Background(), args, &stdout); status != 6 || !bytes.Contains(stdout.Bytes(), []byte("YKC-TRANSCRIPT-001")) {
		t.Fatalf("%d %s", status, stdout.Bytes())
	}
}

func TestRunnerRejectsNonCanonicalNumbers(t *testing.T) {
	runner := Runner{Open: func(coordclient.Config) (ReplayClient, error) { t.Fatal("opened"); return nil, nil }}
	base := []string{"events", "replay", "--base-uri", "https://coord.example", "--channel-id", "channel:test", "--channel-uri", "https://coord.example/channels/test", "--transcript-epoch", "1", "--limit", "100", "--max-records", "1000"}
	for _, changed := range []struct {
		index int
		value string
	}{{9, "01"}, {11, "100x"}, {13, "+1000"}} {
		args := append([]string(nil), base...)
		args[changed.index] = changed.value
		var stdout bytes.Buffer
		if status := runner.Run(context.Background(), args, &stdout); status != 2 {
			t.Fatalf("%v: %d %s", changed, status, stdout.Bytes())
		}
	}
}
