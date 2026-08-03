// Package coordination defines neutral atomic nonce and fenced-lease ports.
package coordination

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidArgument = errors.New("coordination: invalid argument")
	ErrUnavailable     = errors.New("coordination: unavailable")
	ErrConflict        = errors.New("coordination: conflict")
)

type Digest string

type NonceOutcome string

const (
	NonceConsumed NonceOutcome = "consumed"
	NonceReplayed NonceOutcome = "replayed"
)

type NonceValue struct {
	ValueDigest Digest
	ExpiresAt   time.Time
	Epoch       uint64
}

type LeaseValue struct {
	HolderDigest Digest
	ExpiresAt    time.Time
	Epoch        uint64
}

type NonceStore interface {
	Consume(context.Context, Digest, NonceValue) (NonceOutcome, error)
}

type Lease interface {
	FencingToken() uint64
	Renew(context.Context, time.Time) error
	Valid(context.Context) (bool, error)
	Release(context.Context) error
}

type FencedLeaseStore interface {
	Acquire(context.Context, Digest, LeaseValue) (Lease, error)
}
