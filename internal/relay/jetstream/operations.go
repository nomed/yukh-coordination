package jetstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	natsjs "github.com/nats-io/nats.go/jetstream"
	"github.com/nomed/yukh-coordination/internal/relay"
)

const maxMutationAttempts = 64

var _ relay.Store = (*Store)(nil)

func (s *Store) load(ctx context.Context, tenantID string) (*tenantState, string, error) {
	subject, err := TenantSubject(tenantID)
	if err != nil {
		return nil, "", err
	}
	state := newTenantState(tenantID)
	last, err := s.stream.GetLastMsgForSubject(ctx, subject)
	if errors.Is(err, natsjs.ErrMsgNotFound) {
		return state, subject, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("read tenant log head: %w", err)
	}
	consumer, err := s.stream.OrderedConsumer(ctx, natsjs.OrderedConsumerConfig{FilterSubjects: []string{subject}, DeliverPolicy: natsjs.DeliverAllPolicy})
	if err != nil {
		return nil, "", fmt.Errorf("create tenant replay consumer: %w", err)
	}
	defer func() {
		info := consumer.CachedInfo()
		if info == nil || info.Name == "" {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = s.stream.DeleteConsumer(cleanupContext, info.Name)
	}()
	for state.revision < last.Sequence {
		batch, err := consumer.FetchNoWait(256)
		if err != nil {
			return nil, "", fmt.Errorf("fetch tenant log: %w", err)
		}
		progress := false
		for message := range batch.Messages() {
			metadata, metadataErr := message.Metadata()
			if metadataErr != nil {
				return nil, "", fmt.Errorf("inspect tenant command: %w", metadataErr)
			}
			if metadata.Sequence.Stream > last.Sequence {
				break
			}
			if message.Subject() != subject {
				return nil, "", fmt.Errorf("tenant replay subject mismatch")
			}
			if err := state.apply(subject, metadata.Sequence.Stream, message.Data()); err != nil {
				return nil, "", err
			}
			progress = true
		}
		if err := batch.Error(); err != nil {
			return nil, "", fmt.Errorf("replay tenant log: %w", err)
		}
		if !progress {
			return nil, "", fmt.Errorf("tenant log ended before revision %d", last.Sequence)
		}
	}
	return state, subject, nil
}

func (s *Store) publish(ctx context.Context, subject string, revision uint64, data []byte) error {
	if s.publishHook != nil {
		return s.publishHook(ctx, subject, revision, data)
	}
	_, err := s.js.Publish(ctx, subject, data, natsjs.WithExpectStream(StreamName), natsjs.WithExpectLastSequencePerSubject(revision))
	return err
}

func (s *Store) CreateChannel(ctx context.Context, channel relay.Channel) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := relay.ValidateChannel(channel); err != nil {
		return err
	}
	for range maxMutationAttempts {
		state, subject, err := s.load(ctx, channel.Key.TenantID)
		if err != nil {
			return err
		}
		identity := identityOf(channel.Key)
		if existing, ok := state.transcripts[channel.Key]; ok {
			if relay.SameChannel(existing.channel, channel) {
				return nil
			}
			return relay.ErrChannelConflict
		}
		if uri, ok := state.channelURIs[identity]; ok && uri != channel.URI {
			return relay.ErrChannelConflict
		}
		for key, transcript := range state.transcripts {
			if transcript.channel.URI == channel.URI && key.ChannelID != channel.Key.ChannelID {
				return relay.ErrChannelConflict
			}
		}
		data, err := newCommand(channel.Key.TenantID, commandChannelCreated, channelPayload{CanonicalMetadata: encodeBytes(channel.CanonicalMetadata), ChannelID: channel.Key.ChannelID, Lifecycle: channel.Lifecycle, MetadataDigest: channel.MetadataDigest, TranscriptEpoch: channel.Key.TranscriptEpoch, URI: channel.URI})
		if err != nil {
			return err
		}
		if err := s.publish(ctx, subject, state.revision, data); err == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return relay.ErrCommitIndeterminate
}

func (s *Store) LookupChannel(ctx context.Context, key relay.ChannelKey) (relay.Channel, error) {
	if err := ctx.Err(); err != nil {
		return relay.Channel{}, err
	}
	if err := validateKey(key); err != nil {
		return relay.Channel{}, err
	}
	state, _, err := s.load(ctx, key.TenantID)
	if err != nil {
		return relay.Channel{}, err
	}
	t, ok := state.transcripts[key]
	if !ok {
		return relay.Channel{}, relay.ErrChannelNotFound
	}
	return relay.CloneChannel(t.channel), nil
}

func (s *Store) Append(ctx context.Context, intent relay.AppendIntent, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	return s.AppendChecked(ctx, intent, func(relay.AdmissionView) error { return nil }, prepare)
}

func (s *Store) AppendChecked(ctx context.Context, intent relay.AppendIntent, admit relay.Admit, prepare relay.PrepareRecord) (relay.AppendResult, error) {
	if err := ctx.Err(); err != nil {
		return relay.AppendResult{}, err
	}
	if err := relay.ValidateCheckedAppend(intent, admit, prepare); err != nil {
		return relay.AppendResult{}, err
	}
	for range maxMutationAttempts {
		state, subject, err := s.load(ctx, intent.Channel.TenantID)
		if err != nil {
			return relay.AppendResult{}, err
		}
		t, ok := state.transcripts[intent.Channel]
		if !ok {
			return relay.AppendResult{}, relay.ErrChannelNotFound
		}
		if existing, ok := state.events[identityOf(intent.Channel)][intent.EventID]; ok {
			if !sameStoredEvent(existing, intent) {
				return relay.AppendResult{}, relay.ErrEventIDCollision
			}
			return relay.AppendResult{Outcome: relay.AppendOutcomeDuplicate, Record: relay.CloneRecord(existing)}, nil
		}
		if err := admit(stateView{state: state, key: intent.Channel}); err != nil {
			return relay.AppendResult{}, err
		}
		sequence, digest := uint64(len(t.records)+1), relay.EventDigest(intent.CanonicalEvent)
		record, err := prepare(sequence, digest)
		if err != nil {
			return relay.AppendResult{}, fmt.Errorf("prepare accepted record: %w", err)
		}
		if err := relay.ValidatePreparedRecord(intent, sequence, digest, record); err != nil {
			return relay.AppendResult{}, err
		}
		if len(record.Signature) != 0 || record.Sequence > maxJSONSafeInteger {
			return relay.AppendResult{}, relay.ErrInvalidArgument
		}
		if _, duplicate := state.receipts[record.ReceiptID]; duplicate {
			return relay.AppendResult{}, fmt.Errorf("%w: duplicate receipt identity", relay.ErrInvalidArgument)
		}
		payload := recordPayload{AuthenticatedBinding: encodeBytes(record.AuthenticatedBinding), AuthorizationBinding: encodeBytes(record.AuthorizationBinding), CanonicalEvent: encodeBytes(record.CanonicalEvent), ChannelID: record.Channel.ChannelID, EventDigest: record.EventDigest, EventID: record.EventID, ReceiptID: record.ReceiptID, Sequence: record.Sequence, SignatureAlgorithm: record.SignatureAlgorithm, SigningKeyID: record.SigningKeyID, TranscriptEpoch: record.Channel.TranscriptEpoch, UnsignedReceiptPreimage: encodeBytes(record.UnsignedReceiptPreimage)}
		data, err := newCommand(intent.Channel.TenantID, commandRecordAppended, payload)
		if err != nil {
			return relay.AppendResult{}, err
		}
		if err := s.publish(ctx, subject, state.revision, data); err == nil {
			return relay.AppendResult{Outcome: relay.AppendOutcomeAppended, Record: relay.CloneRecord(record)}, nil
		}
		if err := ctx.Err(); err != nil {
			return relay.AppendResult{}, err
		}
	}
	return relay.AppendResult{}, relay.ErrCommitIndeterminate
}

func (s *Store) AttachSignature(ctx context.Context, attachment relay.SignatureAttachment) (relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return relay.AcceptedRecord{}, err
	}
	if err := relay.ValidateSignatureAttachment(attachment); err != nil {
		return relay.AcceptedRecord{}, err
	}
	for range maxMutationAttempts {
		state, subject, err := s.load(ctx, attachment.Channel.TenantID)
		if err != nil {
			return relay.AcceptedRecord{}, err
		}
		record, ok := state.receipts[attachment.ReceiptID]
		if !ok || record.Channel != attachment.Channel {
			return relay.AcceptedRecord{}, relay.ErrReceiptNotFound
		}
		if !bytes.Equal(record.UnsignedReceiptPreimage, attachment.UnsignedReceiptPreimage) {
			return relay.AcceptedRecord{}, relay.ErrSignatureCollision
		}
		if len(record.Signature) != 0 {
			if !bytes.Equal(record.Signature, attachment.Signature) {
				return relay.AcceptedRecord{}, relay.ErrSignatureCollision
			}
			return relay.CloneRecord(record), nil
		}
		payload := signaturePayload{ChannelID: attachment.Channel.ChannelID, PreimageDigest: preimageDigest(attachment.UnsignedReceiptPreimage), ReceiptID: attachment.ReceiptID, Signature: encodeBytes(attachment.Signature), TranscriptEpoch: attachment.Channel.TranscriptEpoch}
		data, err := newCommand(attachment.Channel.TenantID, commandSignatureAttached, payload)
		if err != nil {
			return relay.AcceptedRecord{}, err
		}
		if err := s.publish(ctx, subject, state.revision, data); err == nil {
			record.Signature = bytes.Clone(attachment.Signature)
			return relay.CloneRecord(record), nil
		}
		if err := ctx.Err(); err != nil {
			return relay.AcceptedRecord{}, err
		}
	}
	return relay.AcceptedRecord{}, relay.ErrCommitIndeterminate
}

func (s *Store) Lookup(ctx context.Context, key relay.ChannelKey, eventID string) (relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return relay.AcceptedRecord{}, err
	}
	if err := validateKey(key); err != nil || eventID == "" {
		return relay.AcceptedRecord{}, relay.ErrInvalidArgument
	}
	state, _, err := s.load(ctx, key.TenantID)
	if err != nil {
		return relay.AcceptedRecord{}, err
	}
	if _, ok := state.transcripts[key]; !ok {
		return relay.AcceptedRecord{}, relay.ErrChannelNotFound
	}
	record, ok := state.events[identityOf(key)][eventID]
	if !ok || record.Channel != key {
		return relay.AcceptedRecord{}, relay.ErrEventNotFound
	}
	return relay.CloneRecord(record), nil
}

func (s *Store) Read(ctx context.Context, key relay.ChannelKey, after uint64, limit int) ([]relay.AcceptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateKey(key); err != nil || limit < 1 || limit > 1000 {
		return nil, relay.ErrInvalidArgument
	}
	state, _, err := s.load(ctx, key.TenantID)
	if err != nil {
		return nil, err
	}
	t, ok := state.transcripts[key]
	if !ok {
		return nil, relay.ErrChannelNotFound
	}
	return readTranscript(t, after, limit), nil
}

type stateView struct {
	state *tenantState
	key   relay.ChannelKey
}

func (v stateView) Lookup(eventID string) (relay.AcceptedRecord, error) {
	record, ok := v.state.events[identityOf(v.key)][eventID]
	if !ok || record.Channel != v.key {
		return relay.AcceptedRecord{}, relay.ErrEventNotFound
	}
	return relay.CloneRecord(record), nil
}
func (v stateView) Read(after uint64, limit int) ([]relay.AcceptedRecord, error) {
	if limit < 1 || limit > 1000 {
		return nil, relay.ErrInvalidArgument
	}
	return readTranscript(v.state.transcripts[v.key], after, limit), nil
}

func readTranscript(t *transcript, after uint64, limit int) []relay.AcceptedRecord {
	start := len(t.records)
	if after < uint64(len(t.records)) {
		start = int(after)
	}
	end := min(start+limit, len(t.records))
	result := make([]relay.AcceptedRecord, 0, end-start)
	for _, record := range t.records[start:end] {
		result = append(result, relay.CloneRecord(record))
	}
	return result
}

func validateKey(key relay.ChannelKey) error {
	if key.TenantID == "" || key.ChannelID == "" || key.TranscriptEpoch == "" {
		return relay.ErrInvalidArgument
	}
	return nil
}
