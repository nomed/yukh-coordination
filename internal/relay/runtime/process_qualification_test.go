package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	coordclient "github.com/nomed/yukh-coordination/internal/client"
	"github.com/nomed/yukh-coordination/internal/clientcli"
	"github.com/nomed/yukh-coordination/internal/clientevent"
	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
	"github.com/nomed/yukh-coordination/internal/relay/service"
)

const processQualificationWork = "https://github.com/nomed/yukh-coordination/issues/6"

type processConfig struct {
	Role       string            `json:"role"`
	BaseURI    string            `json:"base_uri"`
	ChannelID  string            `json:"channel_id"`
	ChannelURI string            `json:"channel_uri"`
	Tokens     map[string]string `json:"tokens"`
	Instances  map[string]string `json:"instances"`
	PublicKey  string            `json:"public_key"`
}

type processResult struct {
	Role    string `json:"role"`
	PID     int    `json:"pid"`
	Records int    `json:"records"`
	Digest  string `json:"digest"`
}

type sanitizedRecord struct {
	Sequence    uint64 `json:"sequence"`
	Type        string `json:"type"`
	Participant string `json:"participant"`
}

func TestTwoIsolatedCLIProcessesShareOnlyTheRelayTranscript(t *testing.T) {
	fixture := newRuntimeFixture(t)
	tokens := map[string]string{}
	instances := map[string]string{}
	for index, name := range []string{"A", "B", "C", "D"} {
		tokens[name] = string(bytes.Repeat([]byte(name), 43))
		instances[name] = fmt.Sprintf("019c6f5b-7c00-7000-8000-%012d", 601+index)
	}
	fixture.config.Authenticator = participantAuthenticator{instances: map[string]string{
		tokens["A"]: instances["A"], tokens["B"]: instances["B"],
		tokens["C"]: instances["C"], tokens["D"]: instances["D"],
	}}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.Signer = qualificationSigner{privateKey: privateKey}
	channel := fixture.channel
	channel.Key.TranscriptEpoch = "1"
	if err := fixture.store.CreateChannel(context.Background(), channel); err != nil {
		t.Fatal(err)
	}
	relayRuntime, err := New(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtimeResult := make(chan error, 1)
	go func() { runtimeResult <- relayRuntime.Run(ctx) }()
	waitReady(t, relayRuntime)
	t.Cleanup(func() { cancel(); <-runtimeResult })

	base := processConfig{BaseURI: fixture.baseURL, ChannelID: channel.Key.ChannelID, ChannelURI: channel.URI, Tokens: tokens, Instances: instances, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
	implementation := startQualificationProcess(t, base, "implementation")
	review := startQualificationProcess(t, base, "review")
	implementationResult := waitQualificationProcess(t, implementation)
	reviewResult := waitQualificationProcess(t, review)

	if implementationResult.PID == reviewResult.PID || implementationResult.PID == os.Getpid() || reviewResult.PID == os.Getpid() {
		t.Fatalf("process isolation missing: parent=%d implementation=%d review=%d", os.Getpid(), implementationResult.PID, reviewResult.PID)
	}
	if implementationResult.Records != 15 || reviewResult.Records != 15 || implementationResult.Digest != reviewResult.Digest {
		t.Fatalf("replay mismatch: implementation=%+v review=%+v", implementationResult, reviewResult)
	}
	expected, err := os.ReadFile(filepath.Join(repositoryRoot(t), "internal/relay/runtime/testdata/four-agent-sanitized.json"))
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(bytes.TrimSpace(expected))
	if implementationResult.Digest != "sha-256:"+hex.EncodeToString(expectedDigest[:]) {
		t.Fatalf("published transcript digest changed: %s", implementationResult.Digest)
	}
}

type qualificationProcess struct {
	command *exec.Cmd
	stdout  bytes.Buffer
	stderr  bytes.Buffer
}

func startQualificationProcess(t *testing.T, config processConfig, role string) *qualificationProcess {
	t.Helper()
	config.Role = role
	names := []string{"A", "B"}
	if role == "review" {
		names = []string{"C", "D"}
	}
	tokens, instances := map[string]string{}, map[string]string{}
	for _, name := range names {
		tokens[name], instances[name] = config.Tokens[name], config.Instances[name]
	}
	config.Tokens, config.Instances = tokens, instances
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	process := &qualificationProcess{}
	process.command = exec.Command(os.Args[0], "-test.run=^TestFourAgentProcessHelper$")
	process.command.Env = append(os.Environ(), "YUKH_PROCESS_QUALIFICATION=1")
	process.command.Stdin = bytes.NewReader(raw)
	process.command.Stdout = &process.stdout
	process.command.Stderr = &process.stderr
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if process.command.ProcessState != nil {
			return
		}
		_ = process.command.Process.Kill()
		_ = process.command.Wait()
	})
	return process
}

func waitQualificationProcess(t *testing.T, process *qualificationProcess) processResult {
	t.Helper()
	if err := process.command.Wait(); err != nil {
		t.Fatalf("qualification process: %v: %s", err, process.stderr.Bytes())
	}
	var result processResult
	if err := json.NewDecoder(bytes.NewReader(process.stdout.Bytes())).Decode(&result); err != nil {
		t.Fatalf("qualification output: %v: %q", err, process.stdout.Bytes())
	}
	return result
}

func TestFourAgentProcessHelper(t *testing.T) {
	if os.Getenv("YUKH_PROCESS_QUALIFICATION") != "1" {
		t.Skip("subprocess helper")
	}
	var config processConfig
	if err := json.NewDecoder(os.Stdin).Decode(&config); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} // isolated test certificate
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(config.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid qualification public key")
	}
	clients := map[string]*coordclient.Client{}
	agents := map[string]clientcli.SignalRunner{}
	names := []string{"A", "B"}
	if config.Role == "review" {
		names = []string{"C", "D"}
	}
	for index, name := range names {
		client, err := coordclient.New(coordclient.Config{BaseURI: config.BaseURI, ChannelID: config.ChannelID, ChannelURI: config.ChannelURI, TranscriptEpoch: 1, PageLimit: 100, MaxRecords: 1000}, httpClient, requestAuthorizer{token: config.Tokens[name]}, qualificationReceiptVerifier{validator: validator, publicKey: publicKey})
		if err != nil {
			t.Fatal(err)
		}
		builder, err := clientevent.New(clientevent.Config{ChannelURI: config.ChannelURI, SourceURI: "urn:yukh:source:process-qualification-" + name, Participant: clientevent.Participant{ID: "agent:" + name, Kind: "agent"}, Now: func() time.Time { return time.Date(2026, 8, 5, 19, 0, index, 0, time.UTC) }})
		if err != nil {
			t.Fatal(err)
		}
		clients[name] = client
		agents[name] = clientcli.SignalRunner{Builder: builder, Publisher: client}
	}

	replayClient := clients["A"]
	if config.Role == "implementation" {
		runImplementationSession(t, agents, clients["A"], config.Instances["B"])
	} else if config.Role == "review" {
		runReviewSession(t, agents, clients["C"], httpClient, config)
		replayClient = clients["C"]
	} else {
		t.Fatal("invalid role")
	}
	replay := replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return len(result.Records) == 15 })
	sanitized := sanitizeReplay(t, replay)
	raw, err := json.Marshal(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	result := processResult{Role: config.Role, PID: os.Getpid(), Records: len(replay.Records), Digest: "sha-256:" + hex.EncodeToString(digest[:])}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		t.Fatal(err)
	}
}

type qualificationSigner struct{ privateKey ed25519.PrivateKey }

func (qualificationSigner) Select(context.Context) (service.SigningSelection, error) {
	return service.SigningSelection{KeyID: "qualification-key-1", Algorithm: "ed25519"}, nil
}

func (s qualificationSigner) Sign(_ context.Context, record relay.AcceptedRecord) ([]byte, error) {
	return ed25519.Sign(s.privateKey, record.UnsignedReceiptPreimage), nil
}

type qualificationReceiptVerifier struct {
	validator *protocol.Validator
	publicKey ed25519.PublicKey
}

func (v qualificationReceiptVerifier) Verify(raw []byte) error {
	if err := v.validator.ValidateReceipt(raw); err != nil {
		return err
	}
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return err
	}
	signatureText, ok := receipt["signature"].(string)
	if !ok {
		return fmt.Errorf("missing receipt signature")
	}
	delete(receipt, "signature")
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	unsigned, err = jsoncanonicalizer.Transform(unsigned)
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || !ed25519.Verify(v.publicKey, unsigned, signature) {
		return fmt.Errorf("invalid receipt signature")
	}
	return nil
}

func runImplementationSession(t *testing.T, agents map[string]clientcli.SignalRunner, replayClient *coordclient.Client, recipient string) {
	runSignal(t, agents["A"], "session", "join", map[string]any{"capabilities": []string{"publish", "replay"}, "status": "available", "session_label": "implementation-A"})
	runSignal(t, agents["B"], "session", "join", map[string]any{"capabilities": []string{"publish", "replay"}, "status": "available", "session_label": "implementation-B"})
	replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "join") == 4 })
	claim := runSignal(t, agents["A"], "work", "claim", map[string]any{"work_uri": processQualificationWork, "generation": "0", "scope": "implementation", "boundary": "process qualification", "expected_active_claims": []string{}})
	claimEvent, claimID := stringField(t, claim, "event_id"), stringField(t, claim, "claim_id")
	progress := runSignal(t, agents["A"], "work", "progress", map[string]any{"work_uri": processQualificationWork, "correlation_id": claimEvent, "causation_id": claimEvent, "claim_id": claimID, "generation": "0", "parent_claim_event_id": claimEvent, "status": "ready_for_review", "summary": "flow implemented", "completed": []string{"publish"}, "remaining": []string{"review"}, "blocked_by": []string{}})
	progressEvent := stringField(t, progress, "event_id")
	question := runSignal(t, agents["A"], "question", "ask", map[string]any{"work_uri": processQualificationWork, "body": "Is the receipt valid?", "requested_from": []string{"agent:B"}, "response_required": true})
	questionEvent := stringField(t, question, "event_id")
	runSignal(t, agents["B"], "question", "answer", map[string]any{"work_uri": processQualificationWork, "correlation_id": questionEvent, "question_event_id": questionEvent, "body": "Verified", "disposition": "answered"})
	runSignal(t, agents["A"], "review", "request", map[string]any{"work_uri": processQualificationWork, "claim_id": claimID, "subject": "four-agent flow", "criteria": []string{"verified receipt"}, "independence_required": true})
	replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "verdict") == 1 })
	offer := runSignal(t, agents["A"], "handoff", "offer", map[string]any{"work_uri": processQualificationWork, "correlation_id": claimEvent, "causation_id": progressEvent, "claim_id": claimID, "generation": "0", "parent_claim_event_id": progressEvent, "to_participant_instance_id": recipient, "boundary": "continue qualification", "next_action": "accept ownership", "unresolved_risks": []string{}})
	replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "leave") == 1 })
	accept := runSignal(t, agents["B"], "handoff", "accept", map[string]any{"work_uri": processQualificationWork, "correlation_id": claimEvent, "offer_event_id": stringField(t, offer, "event_id"), "source_claim_event_id": claimEvent, "handoff_id": stringField(t, offer, "handoff_id"), "claim_id": claimID, "generation": "0", "boundary_digest": stringField(t, offer, "boundary_digest"), "evidence_set_digest": stringField(t, offer, "evidence_set_digest")})
	runSignal(t, agents["B"], "work", "claim", map[string]any{"work_uri": processQualificationWork, "generation": "1", "scope": "implementation", "boundary": "successor", "expected_active_claims": []string{claimID}, "predecessor_handoff_event": stringField(t, accept, "event_id")})
	runSignal(t, agents["A"], "work", "release", map[string]any{"work_uri": processQualificationWork, "correlation_id": claimEvent, "causation_id": stringField(t, accept, "event_id"), "claim_id": claimID, "generation": "0", "parent_claim_event_id": stringField(t, accept, "event_id"), "outcome": "superseded", "reason": "handoff complete"})
}

func runReviewSession(t *testing.T, agents map[string]clientcli.SignalRunner, replayClient *coordclient.Client, httpClient *http.Client, config processConfig) {
	replay := replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "join") == 2 })
	stream := openQualificationStream(t, httpClient, config, config.Tokens["C"], replay.HighWaterSequence)
	defer stream.Close()
	scanner := bufio.NewScanner(stream)
	runSignal(t, agents["C"], "session", "join", map[string]any{"capabilities": []string{"publish", "replay"}, "status": "available", "session_label": "review-C"})
	runSignal(t, agents["D"], "session", "join", map[string]any{"capabilities": []string{"publish", "replay"}, "status": "available", "session_label": "review-D"})
	for sequence, participant := range []string{"agent:C", "agent:D"} {
		record := readQualificationSSERecord(t, scanner, replayClient)
		if record.Sequence != replay.HighWaterSequence+uint64(sequence)+1 || record.Type != "join" || record.Participant != participant {
			t.Fatalf("unexpected SSE record: %+v", record)
		}
	}
	replay = replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "review_request") == 1 })
	reviewEvent, evidenceDigest := eventFields(t, replay, "review_request", "id", "evidence_set_digest")
	runSignal(t, agents["C"], "review", "verdict", map[string]any{"work_uri": processQualificationWork, "correlation_id": reviewEvent, "review_event_id": reviewEvent, "evidence_set_digest": evidenceDigest, "outcome": "pass", "summary": "independently verified", "findings": []string{}, "reviewer_independent": true})
	replay = replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "handoff_offer") == 1 })
	offer := replayEventByType(t, replay, "handoff_offer")
	before := len(replay.Records)
	runRejectedSignal(t, agents["C"], "handoff", "accept", map[string]any{
		"work_uri": processQualificationWork, "correlation_id": offer.CorrelationID,
		"offer_event_id": offer.ID, "source_claim_event_id": offer.CorrelationID,
		"handoff_id": offer.Data["handoff_id"], "claim_id": offer.Data["claim_id"],
		"generation": offer.Data["generation"], "boundary_digest": offer.Data["boundary_digest"],
		"evidence_set_digest": offer.Data["evidence_set_digest"],
	})
	replay = replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return len(result.Records) >= before })
	if len(replay.Records) != before || countType(replay, "handoff_accept") != 0 {
		t.Fatalf("wrong-recipient acceptance changed transcript: before=%d after=%d", before, len(replay.Records))
	}
	runSignal(t, agents["D"], "session", "leave", map[string]any{"reason": "wrong-recipient fence observed"})
	replayUntil(t, replayClient, func(result coordclient.ReplayResult) bool { return countType(result, "release") == 1 })
}

func openQualificationStream(t *testing.T, client *http.Client, config processConfig, token string, after uint64) io.ReadCloser {
	t.Helper()
	target := config.BaseURI + "/coordination/v1/channels/" + url.PathEscape(config.ChannelID) + "/transcripts/1/stream"
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set("DPoP", "a.b.c")
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", strconv.FormatUint(after, 10))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("SSE open status=%d content-type=%q body=%s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	return response.Body
}

type qualificationRecordValidator interface {
	ValidateRecord(eventRaw, receiptRaw []byte, expected uint64) (coordclient.Record, error)
}

func readQualificationSSERecord(t *testing.T, scanner *bufio.Scanner, validator qualificationRecordValidator) sanitizedRecord {
	t.Helper()
	record, err := parseQualificationSSERecord(scanner, validator)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func parseQualificationSSERecord(scanner *bufio.Scanner, validator qualificationRecordValidator) (sanitizedRecord, error) {
	var frame []string
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			frame = append(frame, line)
			continue
		}
		if len(frame) == 0 {
			continue
		}
		if len(frame) == 1 && (frame[0] == "retry: 3000" || frame[0] == ": heartbeat") {
			frame = frame[:0]
			continue
		}
		if len(frame) != 3 || !strings.HasPrefix(frame[0], "id: ") || frame[1] != "event: record" || !strings.HasPrefix(frame[2], "data: ") {
			return sanitizedRecord{}, fmt.Errorf("invalid SSE record frame: %q", frame)
		}
		id := strings.TrimPrefix(frame[0], "id: ")
		sequence, err := strconv.ParseUint(id, 10, 64)
		if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != id {
			return sanitizedRecord{}, fmt.Errorf("invalid SSE record id: %q", id)
		}
		data := []byte(strings.TrimPrefix(frame[2], "data: "))
		canonical, err := jsoncanonicalizer.Transform(data)
		if err != nil || !bytes.Equal(canonical, data) {
			return sanitizedRecord{}, fmt.Errorf("non-canonical SSE record data")
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(data, &members) != nil || len(members) != 2 || len(members["event"]) == 0 || len(members["receipt"]) == 0 {
			return sanitizedRecord{}, fmt.Errorf("invalid SSE record shape")
		}
		validated, err := validator.ValidateRecord(members["event"], members["receipt"], sequence)
		if err != nil {
			return sanitizedRecord{}, fmt.Errorf("invalid SSE record binding: %w", err)
		}
		var event struct {
			Type        string `json:"type"`
			Participant struct {
				ID string `json:"id"`
			} `json:"participant"`
		}
		if json.Unmarshal(validated.Event, &event) != nil || event.Type == "" || event.Participant.ID == "" {
			return sanitizedRecord{}, fmt.Errorf("invalid SSE record data")
		}
		return sanitizedRecord{Sequence: sequence, Type: event.Type, Participant: event.Participant.ID}, nil
	}
	if err := scanner.Err(); err != nil {
		return sanitizedRecord{}, fmt.Errorf("read SSE record: %w", err)
	}
	if len(frame) != 0 {
		return sanitizedRecord{}, fmt.Errorf("SSE record missing blank-line terminator: %q", frame)
	}
	return sanitizedRecord{}, fmt.Errorf("SSE ended before record")
}

func TestQualificationSSERecordParserRejectsMalformedFraming(t *testing.T) {
	client, event, receipt := qualificationRecordTestFixture(t)
	validData := string(canonicalQualificationRecord(t, event, receipt))
	tests := map[string]string{
		"missing event":      "id: 3\ndata: " + validData + "\n\n",
		"wrong event":        "id: 3\nevent: boundary-incomplete\ndata: " + validData + "\n\n",
		"duplicate data":     "id: 3\nevent: record\ndata: " + validData + "\ndata: " + validData + "\n\n",
		"noncanonical id":    "id: 03\nevent: record\ndata: " + validData + "\n\n",
		"incomplete framing": "id: 3\nevent: record\ndata: " + validData + "\n",
		"missing receipt":    "id: 3\nevent: record\ndata: {\"event\":" + string(event) + "}\n\n",
		"noncanonical data":  "id: 3\nevent: record\ndata: {\"receipt\":" + string(receipt) + ",\"event\":" + string(event) + "}\n\n",
	}
	for name, stream := range tests {
		t.Run(name, func(t *testing.T) {
			scanner := bufio.NewScanner(strings.NewReader(stream))
			if record, err := parseQualificationSSERecord(scanner, client); err == nil {
				t.Fatalf("accepted malformed frame as %+v", record)
			}
		})
	}
}

func TestQualificationSSERecordParserRequiresCompleteRecordFrame(t *testing.T) {
	client, event, receipt := qualificationRecordTestFixture(t)
	stream := "retry: 3000\n\n: heartbeat\n\nid: 3\nevent: record\ndata: " + string(canonicalQualificationRecord(t, event, receipt)) + "\n\n"
	record, err := parseQualificationSSERecord(bufio.NewScanner(strings.NewReader(stream)), client)
	if err != nil {
		t.Fatal(err)
	}
	if record != (sanitizedRecord{Sequence: 3, Type: "join", Participant: "agent:C"}) {
		t.Fatalf("record = %+v", record)
	}
}

func TestQualificationSSERecordParserRejectsInvalidRecordBindings(t *testing.T) {
	client, event, _ := qualificationRecordTestFixture(t)
	tests := map[string]map[string]any{
		"event id":         {"event_id": "019c6f5b-7c00-7000-8000-000000009999"},
		"event digest":     {"event_digest": "sha-256:" + strings.Repeat("0", 64)},
		"channel id":       {"channel_id": "channel:other"},
		"channel uri":      {"channel_uri": "https://coord.example/channels/other"},
		"transcript epoch": {"transcript_epoch": uint64(2)},
		"sequence":         {"sequence": uint64(4)},
		"cursor":           {"cursor": "4"},
	}
	for name, overrides := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := qualificationRecordReceipt(t, event, overrides, nil)
			stream := "id: 3\nevent: record\ndata: " + string(canonicalQualificationRecord(t, event, receipt)) + "\n\n"
			if record, err := parseQualificationSSERecord(bufio.NewScanner(strings.NewReader(stream)), client); err == nil {
				t.Fatalf("accepted invalid %s binding as %+v", name, record)
			}
		})
	}

	_, _, validReceipt := qualificationRecordTestFixture(t)
	var invalidSignature map[string]any
	if err := json.Unmarshal(validReceipt, &invalidSignature); err != nil {
		t.Fatal(err)
	}
	invalidSignature["signature"] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	receipt := canonicalQualificationJSON(t, invalidSignature)
	stream := "id: 3\nevent: record\ndata: " + string(canonicalQualificationRecord(t, event, receipt)) + "\n\n"
	if record, err := parseQualificationSSERecord(bufio.NewScanner(strings.NewReader(stream)), client); err == nil {
		t.Fatalf("accepted invalid receipt signature as %+v", record)
	}
}

type qualificationRecordSignatureVerifier struct{ publicKey ed25519.PublicKey }

func (v qualificationRecordSignatureVerifier) Verify(raw []byte) error {
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return err
	}
	signatureText, ok := receipt["signature"].(string)
	if !ok {
		return fmt.Errorf("missing signature")
	}
	delete(receipt, "signature")
	unsigned := canonicalQualificationJSONBytes(receipt)
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || !ed25519.Verify(v.publicKey, unsigned, signature) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func qualificationRecordTestFixture(t *testing.T) (*coordclient.Client, []byte, []byte) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	event := canonicalQualificationJSON(t, map[string]any{
		"channel":     "https://coord.example/channels/process-qualification",
		"id":          "019c6f5b-7c00-7000-8000-000000000703",
		"participant": map[string]any{"id": "agent:C", "kind": "agent"},
		"specversion": "0.1",
		"type":        "join",
	})
	receipt := qualificationRecordReceipt(t, event, nil, privateKey)
	client, err := coordclient.New(coordclient.Config{
		BaseURI: "https://coord.example", ChannelID: "channel:process-qualification",
		ChannelURI:      "https://coord.example/channels/process-qualification",
		TranscriptEpoch: 1, PageLimit: 1, MaxRecords: 1,
	}, &http.Client{}, requestAuthorizer{token: "test"}, qualificationRecordSignatureVerifier{publicKey: privateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return client, event, receipt
}

func qualificationRecordReceipt(t *testing.T, event []byte, overrides map[string]any, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	if privateKey == nil {
		privateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	}
	digest := sha256.Sum256(event)
	receipt := map[string]any{
		"channel_id":       "channel:process-qualification",
		"channel_uri":      "https://coord.example/channels/process-qualification",
		"cursor":           "3",
		"event_digest":     "sha-256:" + hex.EncodeToString(digest[:]),
		"event_id":         "019c6f5b-7c00-7000-8000-000000000703",
		"sequence":         uint64(3),
		"specversion":      "0.1",
		"transcript_epoch": uint64(1),
	}
	for name, value := range overrides {
		receipt[name] = value
	}
	unsigned := canonicalQualificationJSON(t, receipt)
	receipt["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	return canonicalQualificationJSON(t, receipt)
}

func canonicalQualificationRecord(t *testing.T, event, receipt []byte) []byte {
	t.Helper()
	return canonicalQualificationJSON(t, map[string]json.RawMessage{"event": event, "receipt": receipt})
}

func canonicalQualificationJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw := canonicalQualificationJSONBytes(value)
	if raw == nil {
		t.Fatal("canonical JSON failed")
	}
	return raw
}

func canonicalQualificationJSONBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil
	}
	return canonical
}

type replayEvent struct {
	ID            string
	CorrelationID string
	Data          map[string]any
}

func replayEventByType(t *testing.T, replay coordclient.ReplayResult, kind string) replayEvent {
	t.Helper()
	for _, record := range replay.Records {
		var event struct {
			ID            string         `json:"id"`
			Type          string         `json:"type"`
			CorrelationID string         `json:"correlation_id"`
			Data          map[string]any `json:"data"`
		}
		if json.Unmarshal(record.Event, &event) == nil && event.Type == kind {
			return replayEvent{ID: event.ID, CorrelationID: event.CorrelationID, Data: event.Data}
		}
	}
	t.Fatal("event not found: " + kind)
	return replayEvent{}
}

func runRejectedSignal(t *testing.T, runner clientcli.SignalRunner, group, action string, input map[string]any) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if status := runner.Run(context.Background(), []string{group, action}, bytes.NewReader(raw), &output); status != 5 || !bytes.Contains(output.Bytes(), []byte(`"code":"YKC-CONFLICT-001"`)) {
		t.Fatalf("%s %s rejection status=%d output=%s", group, action, status, output.Bytes())
	}
}

func replayUntil(t *testing.T, client *coordclient.Client, ready func(coordclient.ReplayResult) bool) coordclient.ReplayResult {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		result, err := client.Replay(context.Background())
		if err == nil && ready(result) {
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transcript condition timed out")
	return coordclient.ReplayResult{}
}

func countType(replay coordclient.ReplayResult, kind string) int {
	count := 0
	for _, record := range replay.Records {
		var event struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(record.Event, &event) == nil && event.Type == kind {
			count++
		}
	}
	return count
}

func eventFields(t *testing.T, replay coordclient.ReplayResult, kind, first, second string) (string, string) {
	t.Helper()
	for _, record := range replay.Records {
		var event struct {
			ID   string         `json:"id"`
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if json.Unmarshal(record.Event, &event) == nil && event.Type == kind {
			values := map[string]string{"id": event.ID}
			for key, value := range event.Data {
				values[key], _ = value.(string)
			}
			return values[first], values[second]
		}
	}
	t.Fatal("event not found: " + kind)
	return "", ""
}

func sanitizeReplay(t *testing.T, replay coordclient.ReplayResult) []sanitizedRecord {
	t.Helper()
	result := make([]sanitizedRecord, 0, len(replay.Records))
	for _, record := range replay.Records {
		var event struct {
			Type        string `json:"type"`
			Participant struct {
				ID string `json:"id"`
			} `json:"participant"`
		}
		if err := json.Unmarshal(record.Event, &event); err != nil {
			t.Fatal(err)
		}
		result = append(result, sanitizedRecord{Sequence: record.Sequence, Type: event.Type, Participant: event.Participant.ID})
	}
	return result
}
