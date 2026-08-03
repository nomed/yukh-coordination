package jetstream

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay"
)

const (
	commandVersion           = "1"
	commandChannelCreated    = "channel_created"
	commandRecordAppended    = "record_appended"
	commandSignatureAttached = "signature_attached"
)

type command struct {
	CommandID      string          `json:"command_id"`
	CommandType    string          `json:"command_type"`
	CommandVersion string          `json:"command_version"`
	Payload        json.RawMessage `json:"payload"`
	TenantID       string          `json:"tenant_id"`
}

type channelPayload struct {
	CanonicalMetadata string `json:"canonical_metadata"`
	ChannelID         string `json:"channel_id"`
	Lifecycle         string `json:"lifecycle"`
	MetadataDigest    string `json:"metadata_digest"`
	TranscriptEpoch   string `json:"transcript_epoch"`
	URI               string `json:"uri"`
}

type recordPayload struct {
	AuthenticatedBinding    string `json:"authenticated_binding"`
	AuthorizationBinding    string `json:"authorization_binding"`
	CanonicalEvent          string `json:"canonical_event"`
	ChannelID               string `json:"channel_id"`
	EventDigest             string `json:"event_digest"`
	EventID                 string `json:"event_id"`
	ReceiptID               string `json:"receipt_id"`
	Sequence                uint64 `json:"sequence"`
	SignatureAlgorithm      string `json:"signature_algorithm"`
	SigningKeyID            string `json:"signing_key_id"`
	TranscriptEpoch         string `json:"transcript_epoch"`
	UnsignedReceiptPreimage string `json:"unsigned_receipt_preimage"`
}

type signaturePayload struct {
	ChannelID       string `json:"channel_id"`
	PreimageDigest  string `json:"preimage_digest"`
	ReceiptID       string `json:"receipt_id"`
	Signature       string `json:"signature"`
	TranscriptEpoch string `json:"transcript_epoch"`
}

func newCommand(tenantID, kind string, payload any) ([]byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("generate command ID: %w", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode command payload: %w", err)
	}
	raw, err := json.Marshal(command{CommandID: id.String(), CommandType: kind, CommandVersion: commandVersion, Payload: payloadBytes, TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("encode command: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize command: %w", err)
	}
	if len(canonical) > int(MaxCommandBytes) {
		return nil, relay.ErrResourceLimit
	}
	return canonical, nil
}

func decodeCommand(raw []byte) (command, error) {
	if len(raw) == 0 || len(raw) > int(MaxCommandBytes) {
		return command{}, fmt.Errorf("invalid command size")
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return command{}, fmt.Errorf("command is not canonical JSON")
	}
	var value command
	if err := decodeClosed(raw, &value); err != nil {
		return command{}, err
	}
	id, err := uuid.Parse(value.CommandID)
	if err != nil || id.Version() != 7 || value.CommandVersion != commandVersion || value.TenantID == "" {
		return command{}, fmt.Errorf("invalid command envelope")
	}
	switch value.CommandType {
	case commandChannelCreated, commandRecordAppended, commandSignatureAttached:
	default:
		return command{}, fmt.Errorf("unknown command type")
	}
	return value, nil
}

func decodeClosed(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode closed command: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing command data")
	}
	return nil
}

func encodeBytes(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func decodeBytes(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("invalid base64url")
	}
	return decoded, nil
}

func preimageDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha-256:" + hex.EncodeToString(digest[:])
}
