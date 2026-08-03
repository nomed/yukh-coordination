// Package protocol validates the accepted Yukh Coordination protocol bytes.
package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"unicode/utf8"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	protocolschema "github.com/nomed/yukh-coordination/schema"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	envelopeURL  = "https://yukh.dev/coordination/schema/envelope-0.1.schema.json"
	metadataURL  = "https://yukh.dev/coordination/schema/channel-metadata-0.1.schema.json"
	receiptURL   = "https://yukh.dev/coordination/schema/receipt-0.1.schema.json"
	maxEventSize = 65_536
	maxDepth     = 16
)

var ErrInvalidEvent = errors.New("protocol: invalid event")

// Event is the server-relevant subset of one validated canonical envelope.
type Event struct {
	ID            string
	Type          string
	ChannelURI    string
	ParticipantID string
	Canonical     []byte
}

// Validator compiles the repository-owned schema once and is safe for
// concurrent validation.
type Validator struct {
	envelope *jsonschema.Schema
	metadata *jsonschema.Schema
	receipt  *jsonschema.Schema
}

func NewValidator() (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := addSchemas(compiler, protocolschema.FS); err != nil {
		return nil, fmt.Errorf("compile protocol schemas: %w", err)
	}
	envelope, err := compiler.Compile(envelopeURL)
	if err != nil {
		return nil, fmt.Errorf("compile event envelope: %w", err)
	}
	metadata, err := compiler.Compile(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("compile channel metadata: %w", err)
	}
	receipt, err := compiler.Compile(receiptURL)
	if err != nil {
		return nil, fmt.Errorf("compile receipt schema: %w", err)
	}
	return &Validator{envelope: envelope, metadata: metadata, receipt: receipt}, nil
}

func (v *Validator) ValidateReceipt(raw []byte) error {
	if v == nil || v.receipt == nil || len(raw) == 0 || len(raw) > 16_384 || !utf8.Valid(raw) {
		return ErrInvalidEvent
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%w: invalid receipt", ErrInvalidEvent)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) || v.receipt.Validate(value) != nil {
		return fmt.Errorf("%w: invalid receipt", ErrInvalidEvent)
	}
	return nil
}

type ChannelMetadata struct {
	TenantID         string
	ChannelID        string
	ChannelURI       string
	ACLPolicyVersion string
	ACLPolicyDigest  string
	Digest           string
}

func (v *Validator) ValidateChannelMetadata(raw []byte) (ChannelMetadata, error) {
	if v == nil || v.metadata == nil || len(raw) == 0 || !utf8.Valid(raw) {
		return ChannelMetadata{}, ErrInvalidEvent
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return ChannelMetadata{}, fmt.Errorf("%w: invalid channel metadata", ErrInvalidEvent)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) || v.metadata.Validate(value) != nil {
		return ChannelMetadata{}, fmt.Errorf("%w: invalid channel metadata", ErrInvalidEvent)
	}
	object := value.(map[string]any)
	digest := sha256.Sum256(append([]byte("yukh.channel-metadata.v0.1\x00"), raw...))
	return ChannelMetadata{
		TenantID: object["tenant_id"].(string), ChannelID: object["channel_id"].(string),
		ChannelURI: object["channel_uri"].(string), ACLPolicyVersion: object["acl_policy_version"].(string),
		ACLPolicyDigest: object["acl_policy_digest"].(string),
		Digest:          fmt.Sprintf("sha-256:%x", digest),
	}, nil
}

// Validate accepts only the exact JCS representation of a schema-valid and
// semantically valid v0.1 event. It never normalizes client input silently.
func (v *Validator) Validate(raw []byte) (Event, error) {
	if v == nil || v.envelope == nil || len(raw) == 0 || len(raw) > maxEventSize || !utf8.Valid(raw) {
		return Event{}, ErrInvalidEvent
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Event{}, fmt.Errorf("%w: event is not canonical JCS", ErrInvalidEvent)
	}
	if err := v.envelope.Validate(value); err != nil {
		return Event{}, fmt.Errorf("%w: schema validation failed", ErrInvalidEvent)
	}
	object := value.(map[string]any)
	if err := validateSemantics(object); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	participant := object["participant"].(map[string]any)
	return Event{
		ID: object["id"].(string), Type: object["type"].(string),
		ChannelURI: object["channel"].(string), ParticipantID: participant["id"].(string),
		Canonical: bytes.Clone(raw),
	}, nil
}

// Canonicalize is exported for qualification tools. Admission must call
// Validate on the original transport bytes and therefore cannot use it to
// repair non-canonical input.
func Canonicalize(raw []byte) ([]byte, error) {
	if _, err := decodeStrict(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalization failed", ErrInvalidEvent)
	}
	return canonical, nil
}

func addSchemas(compiler *jsonschema.Compiler, source fs.FS) error {
	return fs.WalkDir(source, ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return walkErr
		}
		body, err := fs.ReadFile(source, path)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(body, &document); err != nil {
			return err
		}
		object := document.(map[string]any)
		identifier, _ := object["$id"].(string)
		if identifier == "" {
			return fmt.Errorf("schema %s has no $id", path)
		}
		return compiler.AddResource(identifier, document)
	})
}

func decodeStrict(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 1)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				nameToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := nameToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, duplicate := object[name]; duplicate {
					return nil, fmt.Errorf("duplicate member %q", name)
				}
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return array, nil
		}
		return nil, errors.New("unexpected closing delimiter")
	case json.Number:
		return nil, errors.New("client event contains JSON number")
	case string, bool, nil:
		return token, nil
	default:
		return nil, errors.New("unsupported JSON value")
	}
}

func validateSemantics(event map[string]any) error {
	typeName := event["type"].(string)
	data := event["data"].(map[string]any)
	if typeName == "claim" || typeName == "question" || typeName == "review_request" {
		if event["correlation_id"] != event["id"] {
			return errors.New("root correlation mismatch")
		}
	}
	parents := map[string]string{
		"progress": "parent_claim_event_id", "answer": "question_event_id",
		"verdict": "review_event_id", "handoff_offer": "parent_claim_event_id",
		"handoff_accept": "offer_event_id", "release": "parent_claim_event_id",
		"evidence_verification": "referenced_event_id",
	}
	if parent, ok := parents[typeName]; ok && event["causation_id"] != data[parent] {
		return errors.New("causation mismatch")
	}
	if typeName == "presence" && data["valid_until"].(string) <= data["observed_at"].(string) {
		return errors.New("invalid presence interval")
	}
	if typeName == "claim" {
		observed := data["expected_active_claims"].([]any)
		values := make([]string, len(observed))
		for index := range observed {
			values[index] = observed[index].(string)
		}
		if !sort.StringsAreSorted(values) {
			return errors.New("claim observations are not sorted")
		}
	}
	return nil
}
