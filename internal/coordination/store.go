// Package coordination defines neutral atomic nonce and fenced-lease ports.
package coordination

import (
	"context"
	"errors"
	"regexp"
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

// LeaseResumeValue is the closed internal state recovered from an authenticated
// RFC-0015 capability. It must never be formatted as public output.
type LeaseResumeValue struct {
	holderDigest Digest
	expiresAt    time.Time
	epoch        uint64
	fencingToken uint64
}

func (LeaseResumeValue) String() string               { return "LeaseResumeValue{REDACTED}" }
func (LeaseResumeValue) GoString() string             { return "LeaseResumeValue{REDACTED}" }
func (LeaseResumeValue) MarshalJSON() ([]byte, error) { return nil, ErrInvalidArgument }

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

const maxSafeInteger = uint64(9_007_199_254_740_991)

func NewLeaseResumeValue(holderDigest Digest, expiresAt time.Time, epoch, fencingToken uint64) (LeaseResumeValue, error) {
	if !digestPattern.MatchString(string(holderDigest)) || expiresAt.Location() != time.UTC ||
		!expiresAt.Equal(expiresAt.Truncate(time.Millisecond)) || epoch == 0 || epoch > maxSafeInteger ||
		fencingToken == 0 || fencingToken > maxSafeInteger {
		return LeaseResumeValue{}, ErrInvalidArgument
	}
	return LeaseResumeValue{holderDigest: holderDigest, expiresAt: expiresAt, epoch: epoch, fencingToken: fencingToken}, nil
}

func (value LeaseResumeValue) HolderDigest() Digest { return value.holderDigest }
func (value LeaseResumeValue) ExpiresAt() time.Time { return value.expiresAt }
func (value LeaseResumeValue) Epoch() uint64        { return value.epoch }
func (value LeaseResumeValue) FencingToken() uint64 { return value.fencingToken }

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
	Resume(context.Context, Digest, LeaseResumeValue) (Lease, error)
}
