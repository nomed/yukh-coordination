// Package memory implements the relay store in memory for contract tests.
// It is not a production persistence adapter.
package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/nomed/yukh-coordination/internal/relay"
)

type transcript struct {
	channel relay.Channel
	records []relay.AcceptedRecord
}

type Store struct {
	mu          sync.RWMutex
	transcripts map[relay.ChannelKey]*transcript
	channelURIs map[channelIdentity]string
	events      map[channelIdentity]map[string]relay.AcceptedRecord
}

var _ relay.Store = (*Store)(nil)

type channelIdentity struct {
	tenantID  string
	channelID string
}

func New() *Store {
	return &Store{
		transcripts: make(map[relay.ChannelKey]*transcript),
		channelURIs: make(map[channelIdentity]string),
		events:      make(map[channelIdentity]map[string]relay.AcceptedRecord),
	}
}

func (s *Store) CreateChannel(ctx context.Context, channel relay.Channel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if channel.Key.TenantID == "" || channel.Key.ChannelID == "" || channel.Key.TranscriptEpoch == "" || channel.URI == "" {
		return relay.ErrInvalidArgument
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	identity := identityOf(channel.Key)
	if uri, ok := s.channelURIs[identity]; ok && uri != channel.URI {
		return relay.ErrChannelConflict
	}
	if existing, ok := s.transcripts[channel.Key]; ok {
		if existing.channel == channel {
			return nil
		}
		return relay.ErrChannelConflict
	}
	s.channelURIs[identity] = channel.URI
	if s.events[identity] == nil {
		s.events[identity] = make(map[string]relay.AcceptedRecord)
	}
	s.transcripts[channel.Key] = &transcript{channel: channel}
	return nil
}

func (s *Store) Append(ctx context.Context, intent relay.AppendIntent, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return relay.AppendResult{}, err
	}
	if intent.Channel.TenantID == "" || intent.Channel.ChannelID == "" || intent.Channel.TranscriptEpoch == "" || intent.EventID == "" || len(intent.CanonicalEvent) == 0 || prepare == nil {
		return relay.AppendResult{}, relay.ErrInvalidArgument
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.transcripts[intent.Channel]
	if !ok {
		return relay.AppendResult{}, relay.ErrChannelNotFound
	}
	identity := identityOf(intent.Channel)
	if existing, ok := s.events[identity][intent.EventID]; ok {
		if existing.Channel != intent.Channel || !bytes.Equal(existing.CanonicalEvent, intent.CanonicalEvent) {
			return relay.AppendResult{}, relay.ErrEventIDCollision
		}
		return relay.AppendResult{Outcome: relay.AppendOutcomeDuplicate, Record: cloneRecord(existing)}, nil
	}

	digestBytes := sha256.Sum256(intent.CanonicalEvent)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	sequence := uint64(len(t.records) + 1)
	record, err := prepare(sequence, digest)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("prepare accepted record: %w", err)
	}
	if err := validateRecord(intent, sequence, digest, record); err != nil {
		return relay.AppendResult{}, err
	}

	committed := cloneRecord(record)
	t.records = append(t.records, committed)
	s.events[identity][intent.EventID] = committed
	return relay.AppendResult{Outcome: relay.AppendOutcomeAppended, Record: cloneRecord(committed)}, nil
}

func (s *Store) Read(ctx context.Context, key relay.ChannelKey, after uint64, limit int) ([]relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 1000 {
		return nil, relay.ErrInvalidArgument
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.transcripts[key]
	if !ok {
		return nil, relay.ErrChannelNotFound
	}

	start := len(t.records)
	if after < uint64(len(t.records)) {
		start = int(after)
	}
	end := min(start+limit, len(t.records))
	result := make([]relay.AcceptedRecord, 0, end-start)
	for _, record := range t.records[start:end] {
		result = append(result, cloneRecord(record))
	}
	return result, nil
}

func identityOf(key relay.ChannelKey) channelIdentity {
	return channelIdentity{tenantID: key.TenantID, channelID: key.ChannelID}
}

func validateRecord(intent relay.AppendIntent, sequence uint64, digest string, record relay.AcceptedRecord) error {
	if record.Channel != intent.Channel || record.Sequence != sequence || record.EventID != intent.EventID || !bytes.Equal(record.CanonicalEvent, intent.CanonicalEvent) || record.EventDigest != digest {
		return fmt.Errorf("%w: prepared record does not match append intent", relay.ErrInvalidArgument)
	}
	if record.ReceiptID == "" || len(record.AuthenticatedBinding) == 0 || len(record.AuthorizationBinding) == 0 || len(record.UnsignedReceiptPreimage) == 0 {
		return fmt.Errorf("%w: prepared record is incomplete", relay.ErrInvalidArgument)
	}
	return nil
}

func cloneRecord(record relay.AcceptedRecord) relay.AcceptedRecord {
	record.CanonicalEvent = bytes.Clone(record.CanonicalEvent)
	record.AuthenticatedBinding = bytes.Clone(record.AuthenticatedBinding)
	record.AuthorizationBinding = bytes.Clone(record.AuthorizationBinding)
	record.UnsignedReceiptPreimage = bytes.Clone(record.UnsignedReceiptPreimage)
	return record
}
