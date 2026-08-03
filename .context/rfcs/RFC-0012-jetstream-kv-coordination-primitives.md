# RFC-0012: JetStream KV coordination primitives

- Status: Accepted
- Author: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #43
- Governing architecture: ADR-0001, RFC-0002, RFC-0006 and RFC-0011

The project owner accepted this RFC on 2026-08-03. Acceptance authorizes the
separate JetStream KV adapter implementation and synthetic/conformance
qualification. It does not modify RFC-0006 or authorize deployment or live apply.

## Decision requested

Add provider-neutral atomic nonce and fenced-lease ports for external Yukh
components, plus a NATS JetStream KV adapter. Acceptance authorizes a separately
reviewed adapter implementation and conformance tests only. It authorizes no
deployment, approval decision, protected operation or production-readiness claim.

## Compatibility with RFC-0006

RFC-0006 remains fully valid. The authoritative relay Store continues to use one
append-only command log per tenant and uses no KV in its read or write path. KV
cannot hold protocol records, relay indexes, projections, receipts or transcript
authority, and no relay transaction is split across KV and a stream.

This RFC covers a new capability with different semantics: one-time nonce
consumption and temporary exclusive leases. These require direct key lookup,
create-if-absent, revision CAS and fencing, not replayable protocol history.

## Neutral ports

~~~go
type NonceStore interface {
    Consume(ctx context.Context, key Digest, value NonceValue) (NonceOutcome, error)
}

type FencedLeaseStore interface {
    Acquire(ctx context.Context, key Digest, value LeaseValue) (Lease, error)
}

type Lease interface {
    FencingToken() uint64
    Renew(ctx context.Context, expiresAt time.Time) error
    Valid(ctx context.Context) (bool, error)
    Release(ctx context.Context) error
}
~~~

The core ports contain no NATS types. Keys are lowercase SHA-256 digests over
caller-defined canonical scope or nonce material. Values contain schema version,
value digest, expiry and opaque holder digest only. Raw tenant, repository,
Project, issue, participant and approval content are forbidden.

## JetStream KV layout

The adapter owns two buckets, versioned independently from the relay stream:

- `YUKH_COORDINATION_NONCES_V1`;
- `YUKH_COORDINATION_LEASES_V1`.

Configuration requires file storage, explicit replicas, history sufficient for
CAS reconciliation, bounded value size and no mirrors, sources or republish.
Bootstrap is explicit. Existing configuration must match exactly or opening the
adapter fails closed. NATS permissions are limited to the two bucket subjects.

Nonce consumption uses KV `Create`. Existing exact or changed values both return
`replayed`; the caller cannot delete or reuse a nonce. Expiry limits admission
and retention but deletion/TTL is never evidence that a nonce was unused. The
configured retention horizon must exceed the maximum approval lifetime plus the
declared replay-safety window.

Lease acquisition uses `Create` for absence and revision-checked `Update` only
when an observed lease is explicitly expired. Renew and release require the last
owned revision. The successful KV revision is the monotonic fencing token.
Release writes a terminal released value with CAS; it does not delete the key.
Only a later acquire after expiry/release may advance the revision and fencing
token.

## Time, ambiguity and bounds

The caller supplies a trusted UTC time and bounded expiry. The store validates
maximum lifetime and rejects backwards or excessive expiry. Server TTL is cleanup
only. Every protected consumer must validate both unexpired lease and current
fencing token immediately before its irreversible operation.

Each method performs a fixed bounded sequence: one mutation attempt and at most
one exact read to reconcile an ambiguous acknowledgement. It performs no watch,
poll, sleep, background retry or credential switching. Timeout, unavailable KV,
revision ambiguity, mismatched value digest or inability to prove ownership
returns a stable fail-closed error.

## Recovery and security

Backups must include both bucket configuration and retained entries. Restore into
a new epoch invalidates outstanding leases and advances a configured epoch bound
into every value; restored old fencing tokens are never accepted. Credential and
bucket rotation are explicit operational changes. Public diagnostics expose only
stable outcome classes and never keys, values, revisions, endpoints or NATS
provider messages.

Coordination provides atomic storage only. It does not authenticate approvals,
decide plans, hold protected-service credentials or authorize caller operations.

## Qualification

Memory and real disposable `nats-server` tests must cover first nonce consumption,
exact and changed replay, concurrent create, acquire contention, expired acquire,
renew, release, stale-owner rejection, monotonic fencing, ambiguous acknowledgement
reconciliation, timeout/unavailability, configuration mismatch, replica profile,
bounded calls, no polling and restore-epoch fencing.

## Alternatives

- PostgreSQL is unnecessary while NATS JetStream is already an accepted runtime
  dependency and KV supplies the required atomic primitives.
- The RFC-0006 command log remains preferable for relay history but adds needless
  replay and lifecycle machinery for ephemeral leases.
- Process memory, local files and Actions caches cannot provide durable atomic
  replay protection across hosts and are rejected as authoritative adapters.
