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
	eventMediaType      = "application/yukh-event+json;version=0.1"
	receiptMediaType    = "application/yukh-receipt+json;version=0.1"
	transcriptMediaType = "application/yukh-transcript+json;version=0.1"
	maxBodyBytes        = 8 << 20
	maxSafeInteger      = uint64(9_007_199_254_740_991)
)

var (
	ErrInvalidInput   = errors.New("coordination client: invalid input")
	ErrAuthentication = errors.New("coordination client: authentication unavailable")
	ErrAccessDenied   = errors.New("coordination client: access denied")
	ErrConflict       = errors.New("coordination client: conflict")
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

type PublishResult struct {
	Outcome string          `json:"outcome"`
	Receipt json.RawMessage `json:"receipt"`
}

func (c *Client) Publish(ctx context.Context, canonicalEvent []byte) (PublishResult, error) {
	if len(canonicalEvent) == 0 || len(canonicalEvent) > 65_536 {
		return PublishResult{}, ErrInvalidInput
	}
	canonical, err := jsoncanonicalizer.Transform(canonicalEvent)
	if err != nil || !bytes.Equal(canonical, canonicalEvent) {
		return PublishResult{}, ErrInvalidInput
	}
	var event struct {
		SpecVersion string `json:"specversion"`
		ID          string `json:"id"`
		Channel     string `json:"channel"`
	}
	if json.Unmarshal(canonicalEvent, &event) != nil || event.SpecVersion != "0.1" || event.ID == "" || event.Channel != c.config.ChannelURI {
		return PublishResult{}, ErrInvalidInput
	}
	base, _ := url.Parse(c.config.BaseURI)
	base.Path += "/coordination/v1/channels/" + url.PathEscape(c.config.ChannelID) + "/transcripts/" + strconv.FormatUint(c.config.TranscriptEpoch, 10) + "/events"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(canonicalEvent))
	if err != nil {
		return PublishResult{}, ErrInvalidInput
	}
	request.Header.Set("Content-Type", eventMediaType)
	request.Header.Set("Accept", receiptMediaType)
	originalMethod, originalTarget := request.Method, request.URL.String()
	if err := c.authorizer.Authorize(request); err != nil || request.Method != originalMethod || request.URL.String() != originalTarget || len(request.Header.Values("Cookie")) != 0 {
		return PublishResult{}, ErrAuthentication
	}
	response, err := c.http.Do(request)
	if err != nil {
		return PublishResult{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL.String() != request.URL.String() {
		return PublishResult{}, ErrUnavailable
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusUnauthorized:
			return PublishResult{}, ErrAuthentication
		case http.StatusForbidden, http.StatusNotFound:
			return PublishResult{}, ErrAccessDenied
		case http.StatusConflict, http.StatusUnprocessableEntity:
			return PublishResult{}, ErrConflict
		default:
			return PublishResult{}, ErrUnavailable
		}
	}
	if response.Header.Get("Content-Type") != receiptMediaType || !strings.HasPrefix(response.Header.Get("Cache-Control"), "no-store") {
		return PublishResult{}, ErrInvalidRecord
	}
	receipt, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(receipt) == 0 || len(receipt) > maxBodyBytes {
		return PublishResult{}, ErrInvalidRecord
	}
	canonical, err = jsoncanonicalizer.Transform(receipt)
	if err != nil || !bytes.Equal(canonical, receipt) || c.verifier.Verify(receipt) != nil {
		return PublishResult{}, ErrInvalidRecord
	}
	var binding struct {
		SpecVersion     string `json:"specversion"`
		EventID         string `json:"event_id"`
		EventDigest     string `json:"event_digest"`
		ChannelID       string `json:"channel_id"`
		ChannelURI      string `json:"channel_uri"`
		TranscriptEpoch uint64 `json:"transcript_epoch"`
	}
	if json.Unmarshal(receipt, &binding) != nil {
		return PublishResult{}, ErrInvalidRecord
	}
	digest := sha256.Sum256(canonicalEvent)
	if binding.SpecVersion != "0.1" || binding.EventID != event.ID || binding.EventDigest != fmt.Sprintf("sha-256:%x", digest) || binding.ChannelID != c.config.ChannelID || binding.ChannelURI != c.config.ChannelURI || binding.TranscriptEpoch != c.config.TranscriptEpoch {
		return PublishResult{}, ErrInvalidRecord
	}
	outcome := "appended"
	if response.StatusCode == http.StatusOK {
		outcome = "duplicate"
	}
	return PublishResult{Outcome: outcome, Receipt: append(json.RawMessage(nil), receipt...)}, nil
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
		record, err := c.ValidateRecord(item.Event, item.Receipt, expected)
		if err != nil {
			return ReplayResult{}, err
		}
		records = append(records, record)
		expected++
	}
	if page.HighWaterSequence != expected-1 {
		return ReplayResult{}, ErrInvalidRecord
	}
	return ReplayResult{HighWaterSequence: page.HighWaterSequence, Completeness: page.Completeness, BoundarySequence: page.BoundarySequence, Records: records}, nil
}

// ValidateRecord verifies canonical bytes, receipt bindings, sequence, scope, and signature.
func (c *Client) ValidateRecord(eventRaw, receiptRaw []byte, expected uint64) (Record, error) {
	if canonical, err := jsoncanonicalizer.Transform(eventRaw); err != nil || !bytes.Equal(canonical, eventRaw) {
		return Record{}, ErrInvalidRecord
	}
	if canonical, err := jsoncanonicalizer.Transform(receiptRaw); err != nil || !bytes.Equal(canonical, receiptRaw) {
		return Record{}, ErrInvalidRecord
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
		return Record{}, ErrInvalidRecord
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(receiptRaw, &wire) != nil {
		return Record{}, ErrInvalidRecord
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
		return Record{}, ErrInvalidRecord
	}
	digest := sha256.Sum256(eventRaw)
	if event.SpecVersion != "0.1" || receipt.SpecVersion != "0.1" || event.ID == "" || event.Channel != c.config.ChannelURI || receipt.EventID != event.ID || receipt.EventDigest != fmt.Sprintf("sha-256:%x", digest) || receipt.ChannelID != c.config.ChannelID || receipt.ChannelURI != c.config.ChannelURI || receipt.Sequence != expected || receipt.Cursor != strconv.FormatUint(expected, 10) || receipt.TranscriptEpoch != c.config.TranscriptEpoch {
		return Record{}, ErrInvalidRecord
	}
	if err := c.verifier.Verify(receiptRaw); err != nil {
		return Record{}, ErrInvalidRecord
	}
	return Record{Sequence: receipt.Sequence, Event: append(json.RawMessage(nil), eventRaw...), Receipt: append(json.RawMessage(nil), receiptRaw...)}, nil
}
