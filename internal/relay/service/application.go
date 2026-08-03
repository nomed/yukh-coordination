package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay"
	"github.com/nomed/yukh-coordination/internal/relay/httpapi"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

const maxSafeInteger = uint64(9_007_199_254_740_991)

// SubscriptionSource signals that durable state may have advanced. Signals
// carry no transcript data and may be coalesced or spurious.
type SubscriptionSource interface {
	Subscribe(context.Context, relay.ChannelKey, uint64) (<-chan struct{}, func(), error)
	Notify(relay.ChannelKey)
}

type RelayApplication struct {
	store         relay.Store
	appendService *AppendService
	validator     *protocol.Validator
	subscriptions SubscriptionSource
	clock         func() time.Time
	newReceiptID  func() (string, error)
}

var _ httpapi.Application = (*RelayApplication)(nil)

func NewRelayApplication(store relay.Store, appendService *AppendService, validator *protocol.Validator, subscriptions SubscriptionSource) (*RelayApplication, error) {
	if store == nil || appendService == nil || validator == nil || subscriptions == nil {
		return nil, relay.ErrInvalidArgument
	}
	return &RelayApplication{
		store: store, appendService: appendService, validator: validator, subscriptions: subscriptions,
		clock: time.Now,
		newReceiptID: func() (string, error) {
			value, err := uuid.NewV7()
			return value.String(), err
		},
	}, nil
}

func (a *RelayApplication) Append(ctx context.Context, admitted httpapi.AdmittedRequest, body []byte) (httpapi.AppendResponse, error) {
	channel, metadata, epoch, err := a.resolve(ctx, admitted)
	if err != nil {
		return httpapi.AppendResponse{}, err
	}
	event, err := a.validator.Validate(body)
	if err != nil || event.ChannelURI != channel.URI {
		return httpapi.AppendResponse{}, relay.ErrInvalidArgument
	}
	receiptID, err := a.newReceiptID()
	if err != nil {
		return httpapi.AppendResponse{}, fmt.Errorf("create receipt id: %w", err)
	}
	acceptedAt := a.clock().UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	intent := relay.AppendIntent{Channel: admitted.Channel, EventID: event.ID, CanonicalEvent: event.Canonical}
	result, err := a.appendService.Append(ctx, intent, func(sequence uint64, eventDigest string, selection SigningSelection) (relay.AcceptedRecord, error) {
		if sequence == 0 || sequence > maxSafeInteger {
			return relay.AcceptedRecord{}, relay.ErrInvalidArgument
		}
		preimage := receiptDocument{
			SpecVersion: "0.1", ReceiptVersion: "0.1", ReceiptID: receiptID, EventID: event.ID,
			TenantID: admitted.Identity.TenantID, ChannelID: admitted.Channel.ChannelID, ChannelURI: channel.URI,
			PrincipalID: admitted.Identity.PrincipalID, ParticipantID: event.ParticipantID,
			ParticipantInstanceID: admitted.Identity.ParticipantInstanceID, SessionEpoch: admitted.Identity.SessionEpoch,
			Cursor: strconv.FormatUint(sequence, 10), TranscriptEpoch: epoch, Sequence: sequence,
			AcceptedAt: acceptedAt, EventDigest: eventDigest, ChannelMetadataDigest: metadata.Digest,
			ACLPolicyVersion: admitted.ACLPolicyVersion, ACLPolicyDigest: admitted.ACLPolicyDigest,
			ACLDecisionReceiptID: admitted.ACLDecisionReceiptID, AppendOutcome: "appended",
			KeyID: selection.KeyID, SignatureAlgorithm: selection.Algorithm,
		}
		canonicalPreimage, err := canonicalJSON(preimage)
		if err != nil {
			return relay.AcceptedRecord{}, err
		}
		authenticated, err := canonicalJSON(map[string]any{
			"participant_instance_id": admitted.Identity.ParticipantInstanceID,
			"principal_id":            admitted.Identity.PrincipalID, "session_epoch": admitted.Identity.SessionEpoch,
			"tenant_id": admitted.Identity.TenantID,
		})
		if err != nil {
			return relay.AcceptedRecord{}, err
		}
		return relay.AcceptedRecord{
			Channel: admitted.Channel, Sequence: sequence, EventID: event.ID,
			CanonicalEvent: event.Canonical, EventDigest: eventDigest,
			AuthenticatedBinding: authenticated, AuthorizationBinding: admitted.AuthorizationBinding,
			ReceiptID: receiptID, SigningKeyID: selection.KeyID, SignatureAlgorithm: selection.Algorithm,
			UnsignedReceiptPreimage: canonicalPreimage,
		}, nil
	})
	if err != nil {
		return httpapi.AppendResponse{}, err
	}
	if result.Outcome == relay.AppendOutcomeAppended {
		a.subscriptions.Notify(admitted.Channel)
	}
	receipt, err := signedReceipt(result.Record)
	if err != nil {
		return httpapi.AppendResponse{}, err
	}
	if err := a.validator.ValidateReceipt(receipt); err != nil {
		return httpapi.AppendResponse{}, err
	}
	return httpapi.AppendResponse{Outcome: result.Outcome, CanonicalReceipt: receipt}, nil
}

func (a *RelayApplication) Replay(ctx context.Context, request httpapi.ReplayRequest) ([]byte, error) {
	channel, _, epoch, err := a.resolve(ctx, request.AdmittedRequest)
	if err != nil {
		return nil, err
	}
	records, err := a.store.Read(ctx, request.Channel, request.After, request.Limit)
	if err != nil {
		return nil, err
	}
	page, err := buildPage(a.validator, channel, epoch, request.After, records)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(page)
}

func (a *RelayApplication) Stream(ctx context.Context, request httpapi.ReplayRequest) (<-chan httpapi.StreamItem, error) {
	if _, _, _, err := a.resolve(ctx, request.AdmittedRequest); err != nil {
		return nil, err
	}
	notifications, unsubscribe, err := a.subscriptions.Subscribe(ctx, request.Channel, request.After)
	if err != nil {
		return nil, err
	}
	items := make(chan httpapi.StreamItem)
	go func() {
		defer close(items)
		defer unsubscribe()
		cursor := request.After
		for {
			records, err := a.store.Read(ctx, request.Channel, cursor, request.Limit)
			if err != nil {
				sendStreamItem(ctx, items, httpapi.StreamItem{Err: err})
				return
			}
			for _, record := range records {
				if record.Sequence != cursor+1 || len(record.Signature) == 0 {
					boundary := cursor + 1
					sendStreamItem(ctx, items, httpapi.StreamItem{IncompleteBoundary: &boundary})
					return
				}
				encoded, err := canonicalRecord(a.validator, record)
				if err != nil {
					sendStreamItem(ctx, items, httpapi.StreamItem{Err: err})
					return
				}
				if !sendStreamItem(ctx, items, httpapi.StreamItem{Record: &httpapi.StreamRecord{Sequence: record.Sequence, CanonicalRecord: encoded}}) {
					return
				}
				cursor = record.Sequence
			}
			if len(records) == request.Limit {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case _, ok := <-notifications:
				if !ok {
					sendStreamItem(ctx, items, httpapi.StreamItem{Err: errors.New("live subscription closed")})
					return
				}
			}
		}
	}()
	return items, nil
}

func (a *RelayApplication) resolve(ctx context.Context, admitted httpapi.AdmittedRequest) (relay.Channel, protocol.ChannelMetadata, uint64, error) {
	if admitted.Identity.TenantID == "" || admitted.Identity.PrincipalID == "" || admitted.Identity.ParticipantInstanceID == "" ||
		admitted.Channel.TenantID != admitted.Identity.TenantID || len(admitted.AuthorizationBinding) == 0 ||
		admitted.ACLPolicyVersion == "" || admitted.ACLPolicyDigest == "" || admitted.ACLDecisionReceiptID == "" {
		return relay.Channel{}, protocol.ChannelMetadata{}, 0, relay.ErrInvalidArgument
	}
	epoch, err := strconv.ParseUint(admitted.Channel.TranscriptEpoch, 10, 64)
	if err != nil || epoch > maxSafeInteger || admitted.Identity.SessionEpoch > maxSafeInteger {
		return relay.Channel{}, protocol.ChannelMetadata{}, 0, relay.ErrInvalidArgument
	}
	channel, err := a.store.LookupChannel(ctx, admitted.Channel)
	if err != nil {
		return relay.Channel{}, protocol.ChannelMetadata{}, 0, err
	}
	metadata, err := a.validator.ValidateChannelMetadata(channel.CanonicalMetadata)
	if err != nil || metadata.Digest != channel.MetadataDigest || metadata.TenantID != admitted.Identity.TenantID ||
		metadata.ChannelID != admitted.Channel.ChannelID || metadata.ChannelURI != channel.URI ||
		metadata.ACLPolicyVersion != admitted.ACLPolicyVersion || metadata.ACLPolicyDigest != admitted.ACLPolicyDigest || channel.Lifecycle != "active" {
		return relay.Channel{}, protocol.ChannelMetadata{}, 0, relay.ErrChannelNotFound
	}
	return channel, metadata, epoch, nil
}

type receiptDocument struct {
	SpecVersion           string `json:"specversion"`
	ReceiptVersion        string `json:"receipt_version"`
	ReceiptID             string `json:"receipt_id"`
	EventID               string `json:"event_id"`
	TenantID              string `json:"tenant_id"`
	ChannelID             string `json:"channel_id"`
	ChannelURI            string `json:"channel_uri"`
	PrincipalID           string `json:"principal_id"`
	ParticipantID         string `json:"participant_id"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	SessionEpoch          uint64 `json:"session_epoch"`
	Cursor                string `json:"cursor"`
	TranscriptEpoch       uint64 `json:"transcript_epoch"`
	Sequence              uint64 `json:"sequence"`
	AcceptedAt            string `json:"accepted_at"`
	EventDigest           string `json:"event_digest"`
	ChannelMetadataDigest string `json:"channel_metadata_digest"`
	ACLPolicyVersion      string `json:"acl_policy_version"`
	ACLPolicyDigest       string `json:"acl_policy_digest"`
	ACLDecisionReceiptID  string `json:"acl_decision_receipt_id"`
	AppendOutcome         string `json:"append_outcome"`
	KeyID                 string `json:"key_id"`
	SignatureAlgorithm    string `json:"signature_algorithm"`
}

func signedReceipt(record relay.AcceptedRecord) ([]byte, error) {
	if len(record.Signature) == 0 {
		return nil, relay.ErrSignaturePending
	}
	var receipt map[string]any
	if err := json.Unmarshal(record.UnsignedReceiptPreimage, &receipt); err != nil {
		return nil, fmt.Errorf("invalid stored receipt preimage: %w", err)
	}
	canonicalPreimage, err := jsoncanonicalizer.Transform(record.UnsignedReceiptPreimage)
	if err != nil || !bytes.Equal(canonicalPreimage, record.UnsignedReceiptPreimage) ||
		receipt["event_id"] != record.EventID || receipt["event_digest"] != record.EventDigest ||
		receipt["tenant_id"] != record.Channel.TenantID || receipt["channel_id"] != record.Channel.ChannelID ||
		receipt["receipt_id"] != record.ReceiptID || receipt["key_id"] != record.SigningKeyID ||
		receipt["signature_algorithm"] != record.SignatureAlgorithm || receipt["sequence"] != float64(record.Sequence) {
		return nil, errors.New("stored receipt binding mismatch")
	}
	epoch, err := strconv.ParseUint(record.Channel.TranscriptEpoch, 10, 64)
	if err != nil || receipt["transcript_epoch"] != float64(epoch) {
		return nil, errors.New("stored receipt epoch mismatch")
	}
	receipt["signature"] = base64.RawURLEncoding.EncodeToString(record.Signature)
	return canonicalJSON(receipt)
}

func canonicalRecord(validator *protocol.Validator, record relay.AcceptedRecord) ([]byte, error) {
	if relay.EventDigest(record.CanonicalEvent) != record.EventDigest {
		return nil, errors.New("stored event digest mismatch")
	}
	receipt, err := signedReceipt(record)
	if err != nil {
		return nil, err
	}
	if err := validator.ValidateReceipt(receipt); err != nil {
		return nil, err
	}
	var eventValue, receiptValue any
	if json.Unmarshal(record.CanonicalEvent, &eventValue) != nil || json.Unmarshal(receipt, &receiptValue) != nil {
		return nil, errors.New("invalid stored canonical record")
	}
	return canonicalJSON(map[string]any{"event": eventValue, "receipt": receiptValue})
}

func buildPage(validator *protocol.Validator, channel relay.Channel, epoch, after uint64, records []relay.AcceptedRecord) (map[string]any, error) {
	pageRecords := make([]any, 0, len(records))
	highWater := after
	var boundary uint64
	for _, record := range records {
		if record.Sequence != highWater+1 || len(record.Signature) == 0 {
			boundary = highWater + 1
			break
		}
		encoded, err := canonicalRecord(validator, record)
		if err != nil {
			boundary = highWater + 1
			break
		}
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			return nil, err
		}
		pageRecords = append(pageRecords, value)
		highWater = record.Sequence
	}
	page := map[string]any{
		"specversion": "0.1", "channel_id": channel.Key.ChannelID, "channel_uri": channel.URI,
		"transcript_epoch": epoch, "after": after, "high_water_sequence": highWater,
		"completeness": "complete", "records": pageRecords,
	}
	if boundary != 0 {
		page["completeness"] = "incomplete"
		page["boundary_sequence"] = boundary
	}
	return page, nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func sendStreamItem(ctx context.Context, target chan<- httpapi.StreamItem, item httpapi.StreamItem) bool {
	select {
	case target <- item:
		return true
	case <-ctx.Done():
		return false
	}
}
