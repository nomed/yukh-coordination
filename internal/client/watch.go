package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func (c *Client) Watch(ctx context.Context, emit func(Record) error) error {
	if ctx == nil || emit == nil {
		return ErrInvalidInput
	}
	replay, err := c.Replay(ctx)
	if err != nil {
		return err
	}
	for _, record := range replay.Records {
		if emit(record) != nil {
			return ErrUnavailable
		}
	}
	base, _ := url.Parse(c.config.BaseURI)
	base.Path += "/coordination/v1/channels/" + url.PathEscape(c.config.ChannelID) + "/transcripts/" + strconv.FormatUint(c.config.TranscriptEpoch, 10) + "/stream"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return ErrInvalidInput
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", strconv.FormatUint(replay.HighWaterSequence, 10))
	target := request.URL.String()
	if c.authorizer.Authorize(request) != nil || request.URL.String() != target {
		return ErrAuthentication
	}
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || !strings.HasPrefix(response.Header.Get("Cache-Control"), "no-store") {
		return ErrUnavailable
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), maxBodyBytes)
	expected := replay.HighWaterSequence + 1
	frame := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			frame = append(frame, line)
			if len(frame) > 3 {
				return ErrInvalidRecord
			}
			continue
		}
		if len(frame) == 0 {
			continue
		}
		if len(frame) == 1 && (frame[0] == "retry: 3000" || frame[0] == ": heartbeat") {
			frame = frame[:0]
			continue
		}
		if len(frame) == 2 && frame[0] == "event: boundary-incomplete" {
			return ErrIncomplete
		}
		if len(frame) != 3 || frame[0] != "id: "+strconv.FormatUint(expected, 10) || frame[1] != "event: record" || !strings.HasPrefix(frame[2], "data: ") {
			return ErrInvalidRecord
		}
		data := []byte(strings.TrimPrefix(frame[2], "data: "))
		canonical, canonicalErr := jsoncanonicalizer.Transform(data)
		var document struct {
			Event   json.RawMessage `json:"event"`
			Receipt json.RawMessage `json:"receipt"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if canonicalErr != nil || !bytes.Equal(canonical, data) || decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			return ErrInvalidRecord
		}
		record, err := c.ValidateRecord(document.Event, document.Receipt, expected)
		if err != nil || emit(record) != nil {
			return ErrInvalidRecord
		}
		expected++
		frame = frame[:0]
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnavailable
}
