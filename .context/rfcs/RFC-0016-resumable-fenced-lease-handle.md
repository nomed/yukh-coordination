# RFC-0016: Resumable fenced-lease handle

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #59
- Governing architecture: ADR-0001, RFC-0012 and RFC-0015

The project owner explicitly accepted this RFC on 2026-08-03. Acceptance
authorizes the separately reviewed neutral-port and adapter implementation with
deterministic qualification described here. It does not authorize the RFC-0015
HTTP service, deployment, a public listener, credentials, protected consumer
use, publication or live apply.

## Decision requested

Add one provider-neutral operation that reconstructs an RFC-0012 `Lease` from
the closed state recovered from an authenticated RFC-0015 capability.

Acceptance authorizes the separate port/adapter implementation and deterministic
qualification described here. It does not authorize the RFC-0015 HTTP service,
deployment, a public listener, credentials, protected consumer use, publication
or live apply.

## Gap in the accepted contracts

RFC-0012 exposes `Acquire`, which returns one process-local Go `Lease`. Its
`Valid`, `Renew` and `Release` methods depend on unexported key, holder, expiry
and current-revision state. After an RFC-0015 HTTP response completes, or after
the service restarts, no provider-neutral operation can reconstruct that object
from the sealed capability.

Keeping live Go objects in memory would make restart lose ownership. Letting the
HTTP layer read JetStream would expose provider storage and duplicate adapter
semantics. Reacquiring would advance the fence or contend with the still-valid
lease. All three violate accepted requirements.

## Neutral extension

`FencedLeaseStore` gains exactly one operation:

~~~go
type LeaseResumeValue struct {
    HolderDigest Digest
    ExpiresAt    time.Time
    Epoch        uint64
    FencingToken uint64
}

type FencedLeaseStore interface {
    Acquire(context.Context, Digest, LeaseValue) (Lease, error)
    Resume(context.Context, Digest, LeaseResumeValue) (Lease, error)
}
~~~

These signatures are normative in meaning; implementation may use constructors
and unexported fields to keep invalid values unrepresentable.

The key and resume value originate only from successfully opened RFC-0015
capability plaintext inside the primitives application. They are never accepted
as public HTTP members or emitted in diagnostics. `FencingToken` is a positive
JSON-safe integer because RFC-0015 must return it to the protected consumer.

## Exact semantics

`Resume` performs exactly one provider read for the supplied digest key. It
returns a `Lease` only when the current authoritative entry simultaneously:

- is a structurally valid lease record in the configured schema;
- has the configured current epoch;
- has a revision exactly equal to `FencingToken`;
- has holder digest and expiry exactly equal to the resume value;
- is not released;
- is unexpired at the adapter's trusted UTC clock.

Every comparison occurs before returning the handle. The returned `Lease`
contains that exact observed revision and then uses the unchanged RFC-0012 CAS
rules for `Valid`, `Renew` and `Release`.

Missing, deleted, expired, released, changed-holder, changed-expiry,
wrong-epoch, older-revision and newer-revision state return `ErrConflict`. A
provider timeout, unavailable read or ambiguous provider response returns
`ErrUnavailable`. Invalid digest, zero or unsafe fencing token, non-millisecond
expiry or invalid epoch returns `ErrInvalidArgument` before a provider call.
Provider error text and observed state never cross the adapter boundary.

`Resume` does not mutate, acquire, renew, release, reconcile or extend expiry.
It performs no second read, watch, poll, sleep, background task, retry or
credential switch. Concurrent mutation after the read is handled by the
existing revision CAS on the next lease method; a `Valid` result remains only a
point-in-time observation and never replaces downstream fence validation.

## Adapter requirements

The memory adapter implements the same semantics under its existing mutex. The
JetStream KV adapter uses only `Get` on the already accepted leases bucket. It
does not add a subject, bucket, index, stream, value member or configuration
option. RFC-0006 remains byte- and behavior-identical and does not call this
port.

An adapter cannot emulate `Resume` with `Acquire`, cache, process-local registry
or provider-specific type assertion. All production-capable implementations of
`FencedLeaseStore` must implement the operation explicitly.

## Security and recovery

The resume value is security-sensitive internal state. Its formatting is
redacted and it is not serializable by a generic public output path. The sealed
RFC-0015 capability remains responsible for confidentiality, integrity, tenant
binding, expiry and token-version validation before `Resume` is called.

Restore into a new epoch rejects every old capability before or at `Resume`.
Restoring an older KV revision inside the same epoch is not accepted as lease
ownership because the exact fencing token must match; operational recovery must
still follow RFC-0012 epoch advancement rules.

## Qualification

Implementation acceptance requires memory and disposable-NATS tests for:

- exact successful resume followed by valid, renew and release;
- missing, expired, released and malformed records;
- changed key, holder, expiry, epoch and fencing token;
- both older and newer observed revisions;
- one read on success and failure, with zero mutation calls;
- provider timeout/unavailability and sanitized injected provider errors;
- mutation racing immediately after resume, proving the next CAS fails closed;
- restart simulation using only sealed-state fields, with no process registry;
- unchanged RFC-0012 acquire/renew/release conformance and unchanged RFC-0006
  relay tests.

## Compatibility and rollout

This is an additive source-level change to the internal neutral port. Existing
implementations must add `Resume` and will fail compilation until they do;
callers that only acquire leases retain identical runtime behavior. There is no
persistent-data migration and rollback removes the method and its tests.

After this RFC and its implementation are accepted, issue #58 may resume the
RFC-0015 application and HTTP implementation. No operational authorization
follows from either increment.

## Alternatives rejected

### Reacquire the lease

Rejected because a live lease must contend and an expired/released lease would
advance the fencing token rather than reconstruct the sealed ownership state.

### Keep a server-side map of live `Lease` objects

Rejected because it is process-local authority, fails restart and creates an
unbounded cleanup and consistency domain.

### Expose a generic KV read

Rejected because it leaks storage topology and revisions and moves validation,
redaction and provider failures outside the qualified adapter.

### Encode an adapter-specific object in the capability

Rejected because Go implementation state is not a stable client-neutral
contract and would couple capabilities to one provider and binary layout.
