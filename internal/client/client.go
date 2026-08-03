// Package client implements the provider-neutral RFC-0013 read foundation.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	transcriptMediaType = "application/yukh-transcript+json;version=0.1"
	maxBodyBytes        = 8 << 20
	maxSafeInteger      = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidInput   = errors.New("coordination client: invalid input")
	ErrAuthentication = errors.New("coordination client: authentication unavailable")
	ErrAccessDenied   = errors.New("coordination client: access denied")
	ErrIncomplete     = errors.New("coordination client: incomplete transcript")
	ErrUnavailable    = errors.New("coordination client: unavailable")
	ErrInvalidRecord  = errors.New("coordination client: invalid record")
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type RequestAuthorizer interface{ Authorize(*http.Request) error }
type ReceiptVerifier interface{ Verify([]byte) error }

type Config struct {
	BaseURI         string
	ChannelID       string
	ChannelURI      string
	TranscriptEpoch uint64
	PageLimit       int
	MaxRecords      int
}

type Client struct {
	config     Config
	http       HTTPDoer
	authorizer RequestAuthorizer
	verifier   ReceiptVerifier
}

type Record struct {
	Sequence uint64          `json:"sequence"`
	Event    json.RawMessage `json:"event"`
	Receipt  json.RawMessage `json:"receipt"`
}

type ReplayResult struct {
	SpecVersion       string   `json:"specversion"`
	ChannelID         string   `json:"channel_id"`
	ChannelURI        string   `json:"channel_uri"`
	TranscriptEpoch   uint64   `json:"transcript_epoch"`
	HighWaterSequence uint64   `json:"high_water_sequence"`
	Completeness      string   `json:"completeness"`
	BoundarySequence  *uint64  `json:"boundary_sequence,omitempty"`
	Records           []Record `json:"records"`
}

func New(config Config, httpClient HTTPDoer, authorizer RequestAuthorizer, verifier ReceiptVerifier) (*Client, error) {
	base, err := url.Parse(config.BaseURI)
	channel, channelErr := url.Parse(config.ChannelURI)
	if err != nil || channelErr != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.RawPath != "" || strings.HasSuffix(base.Path, "/") || channel.Scheme != "https" || channel.Host == "" || channel.User != nil || channel.RawQuery != "" || channel.Fragment != "" || channel.RawPath != "" || len(config.ChannelURI) > 2048 || config.ChannelID == "" || len(config.ChannelID) > 256 || strings.ContainsAny(config.ChannelID, "/\x00") || config.TranscriptEpoch == 0 || config.TranscriptEpoch > maxSafeInteger || config.PageLimit < 1 || config.PageLimit > 1000 || config.MaxRecords < 1 || config.MaxRecords > 100_000 || httpClient == nil || authorizer == nil || verifier == nil {
		return nil, ErrInvalidInput
	}
	return &Client{config: config, http: httpClient, authorizer: authorizer, verifier: verifier}, nil
}

func (c *Client) Replay(ctx context.Context) (ReplayResult, error) {
	result := ReplayResult{SpecVersion: "0.1", ChannelID: c.config.ChannelID, ChannelURI: c.config.ChannelURI, TranscriptEpoch: c.config.TranscriptEpoch, Completeness: "complete", Records: []Record{}}
	var after uint64
	for {
		page, err := c.page(ctx, after)
		if err != nil {
			return ReplayResult{}, err
		}
		result.Records = append(result.Records, page.Records...)
		result.HighWaterSequence = page.HighWaterSequence
		if len(result.Records) > c.config.MaxRecords {
			return ReplayResult{}, ErrInvalidRecord
		}
		if page.Completeness == "incomplete" {
			result.Completeness, result.BoundarySequence = page.Completeness, page.BoundarySequence
			return result, ErrIncomplete
		}
		if len(page.Records) < c.config.PageLimit {
			return result, nil
		}
		if page.HighWaterSequence <= after {
			return ReplayResult{}, ErrInvalidRecord
		}
		after = page.HighWaterSequence
	}
}

type pageDocument struct {
	SpecVersion       string  `json:"specversion"`
	ChannelID         string  `json:"channel_id"`
	ChannelURI        string  `json:"channel_uri"`
	TranscriptEpoch   uint64  `json:"transcript_epoch"`
	After             uint64  `json:"after"`
	HighWaterSequence uint64  `json:"high_water_sequence"`
	Completeness      string  `json:"completeness"`
	BoundarySequence  *uint64 `json:"boundary_sequence,omitempty"`
	Records           []struct {
		Event   json.RawMessage `json:"event"`
		Receipt json.RawMessage `json:"receipt"`
	} `json:"records"`
}

func (c *Client) page(ctx context.Context, after uint64) (ReplayResult, error) {
	base, _ := url.Parse(c.config.BaseURI)
	base.Path += "/coordination/v1/channels/" + url.PathEscape(c.config.ChannelID) + "/transcripts/" + strconv.FormatUint(c.config.TranscriptEpoch, 10) + "/records"
	query := base.Query()
	query.Set("after", strconv.FormatUint(after, 10))
	query.Set("limit", strconv.Itoa(c.config.PageLimit))
	base.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return ReplayResult{}, ErrInvalidInput
	}
	request.Header.Set("Accept", transcriptMediaType)
	originalMethod, originalTarget := request.Method, request.URL.String()
	if err := c.authorizer.Authorize(request); err != nil {
		return ReplayResult{}, ErrAuthentication
	}
	if request.Method != originalMethod || request.URL.String() != originalTarget || len(request.Header.Values("Cookie")) != 0 {
		return ReplayResult{}, ErrAuthentication
	}
	response, err := c.http.Do(request)
	if err != nil {
		return ReplayResult{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return ReplayResult{}, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return ReplayResult{}, ErrAuthentication
		case http.StatusForbidden, http.StatusNotFound:
			return ReplayResult{}, ErrAccessDenied
		default:
			return ReplayResult{}, ErrUnavailable
		}
	}
	if response.Header.Get("Content-Type") != transcriptMediaType || !strings.HasPrefix(response.Header.Get("Cache-Control"), "no-store") {
		return ReplayResult{}, ErrInvalidRecord
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxBodyBytes {
		return ReplayResult{}, ErrInvalidRecord
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ReplayResult{}, ErrInvalidRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var page pageDocument
	if decoder.Decode(&page) != nil || decoder.Decode(&struct{}{}) != io.EOF || page.SpecVersion != "0.1" || page.ChannelID != c.config.ChannelID || page.ChannelURI != c.config.ChannelURI || page.TranscriptEpoch != c.config.TranscriptEpoch || page.After != after || (page.Completeness != "complete" && page.Completeness != "incomplete") || len(page.Records) > c.config.PageLimit {
		return ReplayResult{}, ErrInvalidRecord
	}
	if page.Completeness == "complete" && page.BoundarySequence != nil || page.Completeness == "incomplete" && (page.BoundarySequence == nil || *page.BoundarySequence != page.HighWaterSequence+1) {
		return ReplayResult{}, ErrInvalidRecord
	}
	records := make([]Record, 0, len(page.Records))
	expected := after + 1
	for _, item := range page.Records {
		sequence, err := c.validateRecord(item.Event, item.Receipt, expected)
		if err != nil {
			return ReplayResult{}, err
		}
		records = append(records, Record{Sequence: sequence, Event: append(json.RawMessage(nil), item.Event...), Receipt: append(json.RawMessage(nil), item.Receipt...)})
		expected++
	}
	if page.HighWaterSequence != expected-1 {
		return ReplayResult{}, ErrInvalidRecord
	}
	return ReplayResult{HighWaterSequence: page.HighWaterSequence, Completeness: page.Completeness, BoundarySequence: page.BoundarySequence, Records: records}, nil
}

func (c *Client) validateRecord(eventRaw, receiptRaw []byte, expected uint64) (uint64, error) {
	if canonical, err := jsoncanonicalizer.Transform(eventRaw); err != nil || !bytes.Equal(canonical, eventRaw) {
		return 0, ErrInvalidRecord
	}
	if canonical, err := jsoncanonicalizer.Transform(receiptRaw); err != nil || !bytes.Equal(canonical, receiptRaw) {
		return 0, ErrInvalidRecord
	}
	var event struct {
		SpecVersion string `json:"specversion"`
		ID          string `json:"id"`
		Channel     string `json:"channel"`
		Work        *struct {
			URI string `json:"uri"`
		} `json:"work,omitempty"`
	}
	var receipt struct {
		SpecVersion, EventID, EventDigest, ChannelID, ChannelURI, Cursor string
		Sequence, TranscriptEpoch                                        uint64
	}
	if json.Unmarshal(eventRaw, &event) != nil {
		return 0, ErrInvalidRecord
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(receiptRaw, &wire) != nil {
		return 0, ErrInvalidRecord
	}
	decodeString := func(name string, target *string) bool {
		raw, ok := wire[name]
		return ok && json.Unmarshal(raw, target) == nil
	}
	decodeUint := func(name string, target *uint64) bool {
		raw, ok := wire[name]
		return ok && json.Unmarshal(raw, target) == nil
	}
	if !decodeString("specversion", &receipt.SpecVersion) || !decodeString("event_id", &receipt.EventID) || !decodeString("event_digest", &receipt.EventDigest) || !decodeString("channel_id", &receipt.ChannelID) || !decodeString("channel_uri", &receipt.ChannelURI) || !decodeString("cursor", &receipt.Cursor) || !decodeUint("sequence", &receipt.Sequence) || !decodeUint("transcript_epoch", &receipt.TranscriptEpoch) {
		return 0, ErrInvalidRecord
	}
	digest := sha256.Sum256(eventRaw)
	if event.SpecVersion != "0.1" || receipt.SpecVersion != "0.1" || event.ID == "" || event.Channel != c.config.ChannelURI || receipt.EventID != event.ID || receipt.EventDigest != fmt.Sprintf("sha-256:%x", digest) || receipt.ChannelID != c.config.ChannelID || receipt.ChannelURI != c.config.ChannelURI || receipt.Sequence != expected || receipt.Cursor != strconv.FormatUint(expected, 10) || receipt.TranscriptEpoch != c.config.TranscriptEpoch {
		return 0, ErrInvalidRecord
	}
	if err := c.verifier.Verify(receiptRaw); err != nil {
		return 0, ErrInvalidRecord
	}
	return receipt.Sequence, nil
}
