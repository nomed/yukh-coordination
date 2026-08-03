// Package memory implements the relay store in memory for contract tests.
// It is not a production persistence adapter.
package memory

import (
	"bytes"
	"context"
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
	if err := relay.ValidateChannel(channel); err != nil {
		return err
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
	if err := relay.ValidateAppendIntent(intent, prepare); err != nil {
		return relay.AppendResult{}, err
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
		return relay.AppendResult{Outcome: relay.AppendOutcomeDuplicate, Record: relay.CloneRecord(existing)}, nil
	}

	digest := relay.EventDigest(intent.CanonicalEvent)
	sequence := uint64(len(t.records) + 1)
	record, err := prepare(sequence, digest)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("prepare accepted record: %w", err)
	}
	if err := relay.ValidatePreparedRecord(intent, sequence, digest, record); err != nil {
		return relay.AppendResult{}, err
	}

	committed := relay.CloneRecord(record)
	t.records = append(t.records, committed)
	s.events[identity][intent.EventID] = committed
	return relay.AppendResult{Outcome: relay.AppendOutcomeAppended, Record: relay.CloneRecord(committed)}, nil
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
		result = append(result, relay.CloneRecord(record))
	}
	return result, nil
}

func identityOf(key relay.ChannelKey) channelIdentity {
	return channelIdentity{tenantID: key.TenantID, channelID: key.ChannelID}
}
