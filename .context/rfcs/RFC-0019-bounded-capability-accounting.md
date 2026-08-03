# RFC-0019: Bounded capability accounting and terminal lease inspection

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #75
- Governing architecture: ADR-0001, RFC-0012, RFC-0015, RFC-0016 and RFC-0017

The project owner explicitly accepted this RFC on 2026-08-03. Acceptance
authorizes only the separately reviewed neutral ports, memory and
JetStream KV adapters, application integration and deterministic qualification
described here. It does not authorize deployment, a public listener, production
credentials, publication, protected consumer use or live apply.

## Decision requested

Close two implementation gaps in accepted RFC-0015:

1. expose a closed, provider-neutral lease inspection result that distinguishes
   `valid`, `expired`, `released` and `stale` after capability authentication;
2. enforce a configured positive limit on active lease capabilities for each
   authenticated tenant/principal across process restart.

Neither function is inferred in the HTTP layer. Both remain internal ports over
provider-owned durable state. RFC-0006 relay routes and storage are unchanged.

## Terminal lease inspection

`FencedLeaseStore` gains a read-only operation with the semantic shape:

~~~go
type LeaseStatus string

const (
    LeaseValid    LeaseStatus = "valid"
    LeaseExpired  LeaseStatus = "expired"
    LeaseReleased LeaseStatus = "released"
    LeaseStale    LeaseStatus = "stale"
)

Inspect(context.Context, Digest, LeaseResumeValue) (LeaseStatus, error)
~~~

The key and resume value originate only from a successfully opened capability.
`Inspect` performs exactly one provider read and no mutation. A structurally
valid record is:

- `valid` when epoch, holder, expiry and revision exactly match, it is not
  released and its expiry is after the trusted clock;
- `expired` when those fields exactly match except that expiry is at or before
  the trusted clock;
- `released` when epoch, holder and expiry match, the terminal release marker is
  set and its revision is exactly the capability revision plus one;
- `stale` for missing state or any other valid changed state.

Malformed stored state is `ErrUnavailable`, not `stale`. Invalid input fails
before a provider call. Provider unavailability is sanitized. There is no
second read, watch, retry, sleep, mutation or observation detail in the result.
The application uses this operation only for the inspect route. Renew and
release retain RFC-0016 `Resume` and its non-enumerating conflict behavior.

## Durable per-principal capability budget

A new provider-neutral `CapabilityBudget` port owns a bounded ledger keyed by a
domain-separated digest of authenticated tenant and principal. Public scope,
holder, repository and provider identifiers never enter the ledger. Each slot
contains only a random capability token ID, expiry, epoch and closed phase.
The configured maximum is positive and no greater than 32.

The application uses one bounded reservation protocol:

1. `Reserve` prunes expired entries, then atomically adds one `pending` token ID
   if a slot exists;
2. lease acquisition runs with the same token ID already selected;
3. `Commit` changes that exact slot to `active` only after acquisition and
   capability sealing succeed;
4. a failed acquisition or seal calls `Cancel` for that exact pending slot;
5. renew uses `Replace` to exchange the old token ID for the replacement token
   and expiry in one CAS;
6. successful release uses `Retire` for the exact token ID.

No successful capability is returned before `Commit`. An ambiguous reservation,
commit, replacement, cancellation or retirement fails closed. It is reconciled
only by one exact read inside the same adapter call. The caller never retries or
switches credentials. A failed cleanup may consume a slot only until its
declared expiry; it cannot grant lease ownership or exceed the configured
maximum.

`pending` and `active` entries share the same maximum. Pending expiry is the
earlier of the requested lease expiry and a configured duration no greater than
five seconds. Pruning occurs only in the foreground operation already requested;
there is no list, watch, timer, polling loop or background cleanup. A ledger
record has a fixed maximum of 32 entries and a fixed maximum encoded size.

The JetStream adapter uses a new, explicitly configured KV bucket distinct from
RFC-0012 nonce and lease buckets. One principal maps to one opaque digest key.
Mutations use create/update CAS plus at most one exact read for ambiguous
acknowledgement. They never enumerate keys or expose bucket, revision or provider
errors. Memory and JetStream implementations have identical semantics.

## Ordering and failure behavior

Authentication, action authorization and scope authorization remain exactly as
accepted by RFC-0017. Budget reservation occurs after both authorization phases
and before lease acquisition. Capability opening precedes `Replace` or `Retire`
and supplies the authenticated token ID; public requests cannot select it.

Budget exhaustion maps to the existing bounded `temporarily_unavailable`
Problem Details shape and performs no lease call. Invalid ledger state is
`invariant_violation`. Provider failure is `temporarily_unavailable`. No failure
contains identity, token ID, expiry, digest, capability, provider body, endpoint,
bucket or revision.

## Recovery and epoch behavior

The budget epoch must equal the coordination and capability epochs at startup.
Mismatch makes the primitives service unready. Restore into a new epoch makes
all earlier ledger entries ineligible and permits bounded replacement of the
principal record on its next foreground operation. Epoch never rolls backward.

Capability-key loss does not delete budget entries. They expire naturally,
which preserves the fail-closed maximum. Rollback removes the primitives service
and budget adapter but does not alter RFC-0006 or RFC-0012 data.

## Required qualification

Acceptance of implementation requires deterministic memory and disposable-NATS
tests proving:

- all four inspection results, malformed state and one-read/zero-mutation bounds;
- limits of 1 and 32, concurrent acquisition and tenant/principal separation;
- exact reserve/commit/cancel/replace/retire ordering and call bounds;
- restart, expiry pruning, ambiguous acknowledgements and provider failure;
- acquisition, sealing, renewal and release failures never exceed the limit;
- epoch mismatch and restore invalidation fail closed;
- no enumeration, polling, sleep, background cleanup or hidden retry;
- complete output and diagnostic redaction;
- unchanged RFC-0006 route and storage tests.

## Compatibility and sequencing

The new internal ports are additive but production-capable primitives
composition must provide them. The inspect HTTP schema gains no member and can
finally emit every already accepted RFC-0015 outcome. The capability envelope
already contains the token ID and does not change. A new JetStream KV bucket is
an operational migration and must be explicitly configured before any future
deployment profile can become ready.

After acceptance, implementation may proceed in issue #75 and unblock final
qualification of #58. It does not make PR #71 mergeable by itself and grants no
deployment, publication or live-operation authority.

## Alternatives rejected

### Process-local counters

Rejected because restart would silently reset authority and permit the limit to
be exceeded.

### Enumerate leases or capabilities

Rejected because it exposes provider topology, creates unbounded work and
requires polling or cleanup scans.

### Collapse every inspection result to stale

Rejected because it cannot implement the already accepted RFC-0015 response
contract and prevents deterministic operator diagnosis.

### Add principal counters to RFC-0012 lease records

Rejected because scope ownership and principal accounting are different keys;
pretending they share one atomic mutation would hide a cross-record transaction
that JetStream KV does not provide.
