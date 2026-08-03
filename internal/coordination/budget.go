package coordination

import (
	"context"
	"encoding/json"
	"time"
)

type CapabilityTokenID [16]byte

func NewCapabilityTokenID(raw [16]byte) (CapabilityTokenID, error) {
	var seen byte
	for _, value := range raw {
		seen |= value
	}
	if seen == 0 {
		return CapabilityTokenID{}, ErrInvalidArgument
	}
	return CapabilityTokenID(raw), nil
}

func (CapabilityTokenID) String() string               { return "CapabilityTokenID{REDACTED}" }
func (CapabilityTokenID) GoString() string             { return "CapabilityTokenID{REDACTED}" }
func (CapabilityTokenID) MarshalJSON() ([]byte, error) { return nil, ErrInvalidArgument }

type CapabilityBudget interface {
	Reserve(context.Context, Digest, CapabilityTokenID, time.Time, uint64) error
	Commit(context.Context, Digest, CapabilityTokenID, uint64) error
	Cancel(context.Context, Digest, CapabilityTokenID, uint64) error
	Replace(context.Context, Digest, CapabilityTokenID, CapabilityTokenID, time.Time, uint64) error
	Retire(context.Context, Digest, CapabilityTokenID, uint64) error
}

var _ json.Marshaler = CapabilityTokenID{}
