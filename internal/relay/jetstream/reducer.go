package jetstream

import (
	"bytes"
	"fmt"

	"github.com/nomed/yukh-coordination/internal/relay"
)

const maxJSONSafeInteger = uint64(9_007_199_254_740_991)

type channelIdentity struct{ tenantID, channelID string }

type transcript struct {
	channel relay.Channel
	records []relay.AcceptedRecord
}

type tenantState struct {
	tenantID    string
	revision    uint64
	transcripts map[relay.ChannelKey]*transcript
	channelURIs map[channelIdentity]string
	events      map[channelIdentity]map[string]relay.AcceptedRecord
	receipts    map[string]relay.AcceptedRecord
}

func newTenantState(tenantID string) *tenantState {
	return &tenantState{tenantID: tenantID, transcripts: map[relay.ChannelKey]*transcript{}, channelURIs: map[channelIdentity]string{}, events: map[channelIdentity]map[string]relay.AcceptedRecord{}, receipts: map[string]relay.AcceptedRecord{}}
}

func (s *tenantState) apply(subject string, revision uint64, raw []byte) error {
	cmd, err := decodeCommand(raw)
	if err != nil {
		return fmt.Errorf("reduce tenant command at stream sequence %d: %w", revision, err)
	}
	expected, _ := TenantSubject(cmd.TenantID)
	if cmd.TenantID != s.tenantID || expected != subject || revision <= s.revision {
		return fmt.Errorf("tenant command binding or order violation")
	}
	switch cmd.CommandType {
	case commandChannelCreated:
		err = s.applyChannel(cmd.Payload)
	case commandRecordAppended:
		err = s.applyRecord(cmd.Payload)
	case commandSignatureAttached:
		err = s.applySignature(cmd.Payload)
	}
	if err != nil {
		return fmt.Errorf("reduce %s at stream sequence %d: %w", cmd.CommandType, revision, err)
	}
	s.revision = revision
	return nil
}

func (s *tenantState) applyChannel(raw []byte) error {
	var payload channelPayload
	if err := decodeClosed(raw, &payload); err != nil {
		return err
	}
	metadata, err := decodeBytes(payload.CanonicalMetadata)
	if err != nil {
		return err
	}
	channel := relay.Channel{Key: relay.ChannelKey{TenantID: s.tenantID, ChannelID: payload.ChannelID, TranscriptEpoch: payload.TranscriptEpoch}, URI: payload.URI, CanonicalMetadata: metadata, MetadataDigest: payload.MetadataDigest, Lifecycle: payload.Lifecycle}
	if err := relay.ValidateChannel(channel); err != nil {
		return err
	}
	identity := identityOf(channel.Key)
	if _, exists := s.transcripts[channel.Key]; exists {
		return fmt.Errorf("duplicate channel command")
	}
	if uri, exists := s.channelURIs[identity]; exists && uri != channel.URI {
		return relay.ErrChannelConflict
	}
	for key, transcript := range s.transcripts {
		if key.TenantID == s.tenantID && transcript.channel.URI == channel.URI && key.ChannelID != channel.Key.ChannelID {
			return relay.ErrChannelConflict
		}
	}
	s.channelURIs[identity] = channel.URI
	if s.events[identity] == nil {
		s.events[identity] = map[string]relay.AcceptedRecord{}
	}
	s.transcripts[channel.Key] = &transcript{channel: relay.CloneChannel(channel)}
	return nil
}

func (s *tenantState) applyRecord(raw []byte) error {
	var payload recordPayload
	if err := decodeClosed(raw, &payload); err != nil {
		return err
	}
	if payload.Sequence == 0 || payload.Sequence > maxJSONSafeInteger {
		return fmt.Errorf("record sequence is outside the JSON safe-integer range")
	}
	event, err := decodeBytes(payload.CanonicalEvent)
	if err != nil {
		return err
	}
	authn, err := decodeBytes(payload.AuthenticatedBinding)
	if err != nil {
		return err
	}
	authz, err := decodeBytes(payload.AuthorizationBinding)
	if err != nil {
		return err
	}
	preimage, err := decodeBytes(payload.UnsignedReceiptPreimage)
	if err != nil {
		return err
	}
	key := relay.ChannelKey{TenantID: s.tenantID, ChannelID: payload.ChannelID, TranscriptEpoch: payload.TranscriptEpoch}
	t, exists := s.transcripts[key]
	if !exists {
		return relay.ErrChannelNotFound
	}
	record := relay.AcceptedRecord{Channel: key, Sequence: payload.Sequence, EventID: payload.EventID, CanonicalEvent: event, EventDigest: payload.EventDigest, AuthenticatedBinding: authn, AuthorizationBinding: authz, ReceiptID: payload.ReceiptID, SigningKeyID: payload.SigningKeyID, SignatureAlgorithm: payload.SignatureAlgorithm, UnsignedReceiptPreimage: preimage}
	intent := relay.AppendIntent{Channel: key, EventID: record.EventID, CanonicalEvent: record.CanonicalEvent}
	if err := relay.ValidatePreparedRecord(intent, uint64(len(t.records)+1), relay.EventDigest(event), record); err != nil {
		return err
	}
	identity := identityOf(key)
	if _, exists := s.events[identity][record.EventID]; exists {
		return relay.ErrEventIDCollision
	}
	if _, exists := s.receipts[record.ReceiptID]; exists {
		return fmt.Errorf("duplicate receipt identity")
	}
	t.records = append(t.records, relay.CloneRecord(record))
	s.events[identity][record.EventID] = relay.CloneRecord(record)
	s.receipts[record.ReceiptID] = relay.CloneRecord(record)
	return nil
}

func (s *tenantState) applySignature(raw []byte) error {
	var payload signaturePayload
	if err := decodeClosed(raw, &payload); err != nil {
		return err
	}
	signature, err := decodeBytes(payload.Signature)
	if err != nil || len(signature) == 0 {
		return fmt.Errorf("invalid signature")
	}
	key := relay.ChannelKey{TenantID: s.tenantID, ChannelID: payload.ChannelID, TranscriptEpoch: payload.TranscriptEpoch}
	record, exists := s.receipts[payload.ReceiptID]
	if !exists || record.Channel != key {
		return relay.ErrReceiptNotFound
	}
	if preimageDigest(record.UnsignedReceiptPreimage) != payload.PreimageDigest || len(record.Signature) != 0 {
		return relay.ErrSignatureCollision
	}
	record.Signature = signature
	t := s.transcripts[key]
	t.records[record.Sequence-1] = relay.CloneRecord(record)
	s.events[identityOf(key)][record.EventID] = relay.CloneRecord(record)
	s.receipts[record.ReceiptID] = relay.CloneRecord(record)
	return nil
}

func identityOf(key relay.ChannelKey) channelIdentity {
	return channelIdentity{tenantID: key.TenantID, channelID: key.ChannelID}
}

func sameStoredEvent(record relay.AcceptedRecord, intent relay.AppendIntent) bool {
	return record.Channel == intent.Channel && record.EventID == intent.EventID && bytes.Equal(record.CanonicalEvent, intent.CanonicalEvent)
}
