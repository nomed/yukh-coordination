// Package relay defines the persistence boundary of the reference relay.
package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrChannelNotFound     = errors.New("relay: channel not found")
	ErrChannelConflict     = errors.New("relay: channel metadata conflict")
	ErrEventIDCollision    = errors.New("relay: event ID collision")
	ErrInvalidArgument     = errors.New("relay: invalid argument")
	ErrCommitIndeterminate = errors.New("relay: commit outcome indeterminate")
	ErrReceiptNotFound     = errors.New("relay: receipt not found")
	ErrSignatureCollision  = errors.New("relay: receipt signature collision")
	ErrEventNotFound       = errors.New("relay: event not found")
	ErrSignaturePending    = errors.New("relay: durable signature pending")
)

// ChannelKey identifies one immutable transcript epoch.
type ChannelKey struct {
	TenantID        string
	ChannelID       string
	TranscriptEpoch string
}

// Channel is the immutable relay metadata for one transcript epoch.
type Channel struct {
	Key ChannelKey
	URI string
}

// AppendIntent is the stable client material used for idempotency.
type AppendIntent struct {
	Channel        ChannelKey
	EventID        string
	CanonicalEvent []byte
}

// AcceptedRecord is the material committed atomically by an append adapter.
// Bindings and UnsignedReceiptPreimage are already canonical representations;
// their schemas remain governed by RFC-0001 and RFC-0002.
type AcceptedRecord struct {
	Channel                 ChannelKey
	Sequence                uint64
	EventID                 string
	CanonicalEvent          []byte
	EventDigest             string
	AuthenticatedBinding    []byte
	AuthorizationBinding    []byte
	ReceiptID               string
	SigningKeyID            string
	SignatureAlgorithm      string
	UnsignedReceiptPreimage []byte
	Signature               []byte
}

// SignatureAttachment identifies the exact persisted receipt preimage whose
// externally produced signature must be attached.
type SignatureAttachment struct {
	Channel                 ChannelKey
	ReceiptID               string
	UnsignedReceiptPreimage []byte
	Signature               []byte
}

// PrepareRecord finishes an accepted record after the adapter has allocated
// its sequence. It must be deterministic, side-effect free and bounded.
type PrepareRecord func(sequence uint64, eventDigest string) (AcceptedRecord, error)

type AppendOutcome string

const (
	AppendOutcomeAppended  AppendOutcome = "appended"
	AppendOutcomeDuplicate AppendOutcome = "duplicate"
)

type AppendResult struct {
	Outcome AppendOutcome
	Record  AcceptedRecord
}

// Store is the transport-neutral append and replay persistence port.
type Store interface {
	CreateChannel(context.Context, Channel) error
	Lookup(context.Context, ChannelKey, string) (AcceptedRecord, error)
	Append(context.Context, AppendIntent, PrepareRecord) (AppendResult, error)
	AttachSignature(context.Context, SignatureAttachment) (AcceptedRecord, error)
	Read(context.Context, ChannelKey, uint64, int) ([]AcceptedRecord, error)
}

// SameEvent reports whether two intents carry byte-identical accepted input.
func SameEvent(left, right AppendIntent) bool {
	return left.EventID == right.EventID && bytes.Equal(left.CanonicalEvent, right.CanonicalEvent)
}

// ValidateChannel enforces the adapter-independent channel contract.
func ValidateChannel(channel Channel) error {
	if channel.Key.TenantID == "" || channel.Key.ChannelID == "" || channel.Key.TranscriptEpoch == "" || channel.URI == "" {
		return ErrInvalidArgument
	}
	return nil
}

// ValidateAppendIntent enforces the adapter-independent append input contract.
func ValidateAppendIntent(intent AppendIntent, prepare PrepareRecord) error {
	if err := ValidateIntent(intent); err != nil {
		return err
	}
	if prepare == nil {
		return ErrInvalidArgument
	}
	return nil
}

// ValidateIntent enforces the stable client material independently from the
// adapter-specific preparation callback.
func ValidateIntent(intent AppendIntent) error {
	if intent.Channel.TenantID == "" || intent.Channel.ChannelID == "" || intent.Channel.TranscriptEpoch == "" || intent.EventID == "" || len(intent.CanonicalEvent) == 0 {
		return ErrInvalidArgument
	}
	return nil
}

// EventDigest returns the frozen digest representation for canonical bytes.
func EventDigest(canonicalEvent []byte) string {
	digest := sha256.Sum256(canonicalEvent)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ValidatePreparedRecord ensures record preparation cannot change the intent
// or omit material that must commit atomically.
func ValidatePreparedRecord(intent AppendIntent, sequence uint64, digest string, record AcceptedRecord) error {
	if record.Channel != intent.Channel || record.Sequence != sequence || record.EventID != intent.EventID || !bytes.Equal(record.CanonicalEvent, intent.CanonicalEvent) || record.EventDigest != digest {
		return fmt.Errorf("%w: prepared record does not match append intent", ErrInvalidArgument)
	}
	if record.ReceiptID == "" || record.SigningKeyID == "" || record.SignatureAlgorithm == "" || len(record.AuthenticatedBinding) == 0 || len(record.AuthorizationBinding) == 0 || len(record.UnsignedReceiptPreimage) == 0 {
		return fmt.Errorf("%w: prepared record is incomplete", ErrInvalidArgument)
	}
	return nil
}

// CloneRecord returns a defensive copy of all committed byte material.
func CloneRecord(record AcceptedRecord) AcceptedRecord {
	record.CanonicalEvent = bytes.Clone(record.CanonicalEvent)
	record.AuthenticatedBinding = bytes.Clone(record.AuthenticatedBinding)
	record.AuthorizationBinding = bytes.Clone(record.AuthorizationBinding)
	record.UnsignedReceiptPreimage = bytes.Clone(record.UnsignedReceiptPreimage)
	record.Signature = bytes.Clone(record.Signature)
	return record
}

// ValidateSignatureAttachment enforces the adapter-independent attachment
// contract. Signing remains outside the Store failure domain.
func ValidateSignatureAttachment(attachment SignatureAttachment) error {
	if attachment.Channel.TenantID == "" || attachment.Channel.ChannelID == "" || attachment.Channel.TranscriptEpoch == "" || attachment.ReceiptID == "" || len(attachment.UnsignedReceiptPreimage) == 0 || len(attachment.Signature) == 0 {
		return ErrInvalidArgument
	}
	return nil
}
