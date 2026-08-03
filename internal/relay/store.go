// Package relay defines the persistence boundary of the reference relay.
package relay

import (
	"bytes"
	"context"
	"errors"
)

var (
	ErrChannelNotFound  = errors.New("relay: channel not found")
	ErrChannelConflict  = errors.New("relay: channel metadata conflict")
	ErrEventIDCollision = errors.New("relay: event ID collision")
	ErrInvalidArgument  = errors.New("relay: invalid argument")
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
	UnsignedReceiptPreimage []byte
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
	Append(context.Context, AppendIntent, PrepareRecord) (AppendResult, error)
	Read(context.Context, ChannelKey, uint64, int) ([]AcceptedRecord, error)
}

// SameEvent reports whether two intents carry byte-identical accepted input.
func SameEvent(left, right AppendIntent) bool {
	return left.EventID == right.EventID && bytes.Equal(left.CanonicalEvent, right.CanonicalEvent)
}
