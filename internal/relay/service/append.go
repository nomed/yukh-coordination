// Package service implements transport-neutral relay use cases.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/nomed/yukh-coordination/internal/relay"
)

// SigningSelection identifies an eligible key before a new append transaction
// begins. PrepareRecord must bind both fields into the receipt preimage.
type SigningSelection struct {
	KeyID     string
	Algorithm string
}

// Signer is outside the Store failure domain. Sign must resolve the key bound
// into the persisted preimage and must never replace that selection.
type Signer interface {
	Select(context.Context) (SigningSelection, error)
	Sign(context.Context, relay.AcceptedRecord) ([]byte, error)
}

type PrepareRecord func(sequence uint64, eventDigest string, selection SigningSelection) (relay.AcceptedRecord, error)

type AppendService struct {
	store  relay.Store
	signer Signer
}

func NewAppendService(store relay.Store, signer Signer) (*AppendService, error) {
	if store == nil || signer == nil {
		return nil, relay.ErrInvalidArgument
	}
	return &AppendService{store: store, signer: signer}, nil
}

// Append returns success only after the accepted record has a durable
// signature. A signing failure leaves the append recoverable by exact retry and
// returns ErrSignaturePending rather than an unsigned success result.
func (s *AppendService) Append(ctx context.Context, intent relay.AppendIntent, prepare PrepareRecord) (relay.AppendResult, error) {
	return s.AppendChecked(ctx, intent, func(relay.AdmissionView) error { return nil }, prepare)
}

func (s *AppendService) AppendChecked(ctx context.Context, intent relay.AppendIntent, admit relay.Admit, prepare PrepareRecord) (relay.AppendResult, error) {
	if admit == nil || prepare == nil {
		return relay.AppendResult{}, relay.ErrInvalidArgument
	}
	if err := relay.ValidateIntent(intent); err != nil {
		return relay.AppendResult{}, err
	}

	existing, err := s.store.Lookup(ctx, intent.Channel, intent.EventID)
	switch {
	case err == nil:
		if existing.Channel != intent.Channel || !bytes.Equal(existing.CanonicalEvent, intent.CanonicalEvent) {
			return relay.AppendResult{}, relay.ErrEventIDCollision
		}
		return s.ensureSigned(ctx, relay.AppendResult{Outcome: relay.AppendOutcomeDuplicate, Record: existing})
	case errors.Is(err, relay.ErrEventNotFound):
	case err != nil:
		return relay.AppendResult{}, err
	}

	selection, err := s.signer.Select(ctx)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("select receipt signing key: %w", err)
	}
	if selection.KeyID == "" || selection.Algorithm == "" {
		return relay.AppendResult{}, fmt.Errorf("%w: incomplete signing selection", relay.ErrInvalidArgument)
	}
	result, err := s.store.AppendChecked(ctx, intent, admit, func(sequence uint64, digest string) (relay.AcceptedRecord, error) {
		record, err := prepare(sequence, digest, selection)
		if err != nil {
			return relay.AcceptedRecord{}, err
		}
		if record.SigningKeyID != selection.KeyID || record.SignatureAlgorithm != selection.Algorithm {
			return relay.AcceptedRecord{}, fmt.Errorf("%w: prepared receipt changed signing selection", relay.ErrInvalidArgument)
		}
		return record, nil
	})
	if err != nil {
		return relay.AppendResult{}, err
	}
	return s.ensureSigned(ctx, result)
}

func (s *AppendService) ensureSigned(ctx context.Context, result relay.AppendResult) (relay.AppendResult, error) {
	if len(result.Record.Signature) > 0 {
		return result, nil
	}
	signature, err := s.signer.Sign(ctx, result.Record)
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("%w: sign receipt: %v", relay.ErrSignaturePending, err)
	}
	signed, err := s.store.AttachSignature(ctx, relay.SignatureAttachment{
		Channel: result.Record.Channel, ReceiptID: result.Record.ReceiptID,
		UnsignedReceiptPreimage: result.Record.UnsignedReceiptPreimage,
		Signature:               signature,
	})
	if err != nil {
		return relay.AppendResult{}, fmt.Errorf("%w: persist receipt signature: %v", relay.ErrSignaturePending, err)
	}
	result.Record = signed
	return result, nil
}
