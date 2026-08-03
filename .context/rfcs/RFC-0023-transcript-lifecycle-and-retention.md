# RFC-0023: Single-node transcript lifecycle and retention

- Status: Draft
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #133
- Governing architecture: RFC-0001, RFC-0002, RFC-0003, RFC-0007, RFC-0008 and RFC-0011

Acceptance authorizes only separately reviewed implementation and hermetic
qualification. It does not authorize destructive execution, deployment,
production use, retention-policy selection for an adopter or deletion of real
data or backups.

## Summary

Freeze the separate administrative transcript-lifecycle boundary required by
RFC-0008 before the single-node relay executable may accept its first event.
Every channel binds one explicit finite retention policy before admission.
Expiry, selective redaction and whole-transcript deletion are monotonic,
audited operations that make the affected transcript non-active and
incomplete. They never rewrite history into an apparently complete transcript.

The ordinary `relay.Store` and public HTTP/SSE surface gain no destructive
authority. A separate SQLite lifecycle port and accountable offline worker own
the operation. Because the event, identity, security-audit, signer and backup
domains cannot commit atomically, lifecycle uses a fail-closed recoverable saga
with one immutable operation identity and durable evidence at every boundary.

## Motivation

The relay already qualifies append, replay, signing, authentication,
authorization, audit and bounded runtime behavior. It must still refuse event
admission because accepted RFCs require finite declared retention and honest
evidence after removal. Adding a process binary without this boundary would
silently turn indefinite storage into a default policy and make deletion
indistinguishable from data that was never accepted.

Destructive work also crosses multiple failure domains. Pretending that an
event database transaction can atomically delete external backups or append to
a separate audit ledger would create an unsafe recovery story. This RFC makes
partial progress explicit and retryable without repeating destructive steps.

## Goals

- bind one explicit finite policy and policy digest before first append;
- keep lifecycle administration outside ordinary append/replay credentials;
- preserve immutable evidence that accepted history existed after payload
  removal;
- make redacted/deleted transcripts incomplete and projection-ineligible;
- separate epochs monotonically and forbid identifier reuse;
- require export evidence before destruction when policy permits or requires;
- track event, identity and audit backup-deletion obligations explicitly;
- recover deterministically after crashes, ambiguous signer outcomes and clock
  rollback;
- provide bounded, redacted administrative and security-audit evidence.

## Non-goals

- a public administration API, user self-service deletion or legal-hold system;
- policy selection, jurisdictional compliance claims or adopter data
  classification;
- changing accepted canonical event bytes in place;
- adding destructive methods to `relay.Store`;
- JetStream lifecycle, federation, multi-node execution or distributed sagas;
- automatic epoch rollover, retention extension or best-effort deletion;
- deployment, execution against real data or production authorization.

## Policy and channel binding

One closed canonical policy document is signed and referenced by the accepted
RFC-0008 channel manifest. It contains exactly:

- schema/profile version and opaque policy ID;
- positive policy epoch and lowercase SHA-256 policy digest;
- positive finite active-retention duration in milliseconds;
- positive finite event-backup deletion window;
- positive finite identity-backup deletion window;
- positive finite security-audit-backup deletion window;
- export mode: `forbidden`, `permitted` or `required`;
- redaction and whole-deletion authority role IDs;
- one selection from the closed integrity-retention profiles defined below;
- issue/activation time and accountable policy approver.

There is no default, inheritance, zero/infinite duration, wildcard authority or
silent grace period. Durations are positive integers no greater than the JSON
safe-integer bound. The implementation additionally applies closed operational
limits selected by the profile; exceeding them rejects the policy rather than
clamping it.

Before sequence 1, channel metadata binds the exact policy ID, epoch and digest
and records one policy-activation security-audit receipt. The event database
refuses append when this binding is absent, malformed, inactive or different
from the active signed manifest. A higher policy epoch applies only to a new
transcript epoch; it cannot extend or rewrite the retention deadline of an
existing epoch.

The retention deadline is derived once from the accepted transcript creation
time and bound duration, stored as an exact UTC millisecond, and never recomputed
from current configuration.

The first integrity-retention profile is fixed to server sequence, event-ID
digest, canonical event digest, signed receipt reference and lifecycle operation
reference. It retains no event payload, work URI, participant label or arbitrary
metadata. Future profiles require a new accepted RFC; manifests cannot invent
fields.

## Lifecycle model

Each transcript epoch has two independent persisted dimensions:

- completeness: `complete` or `incomplete`;
- lifecycle: `active`, `redacted` or `deleted`.

Only `active` plus `complete` may assert final work, claim, handoff, review or
presence projections. Starting any lifecycle operation immediately fences new
append and live delivery for that epoch. The public read contract reports the
last durably completed lifecycle and any closed `transition_pending` boundary;
it never serves records beyond an uncertain destructive boundary.

Lifecycle transitions are monotonic:

```text
active -> redacted
active -> deleted
redacted -> deleted
```

No transition returns to `active`. Continued channel use requires an explicit
successor epoch with a higher positive epoch, newly bound policy and distinct
creation receipt. Successor creation is never an automatic side effect of
redaction, deletion or process restart.

Event IDs, receipt IDs, lifecycle operation IDs and transcript epochs are never
reused, including after deletion or restore. The SQLite adapter retains a
restricted non-public cross-epoch digest registry sufficient to reject reuse
without retaining removed payload bytes. It is administrative non-reuse state,
not part of the deleted transcript representation; public replay still exposes
only the policy-permitted deletion receipt.

## Separate administrative port

The single-node SQLite adapter implements a new `TranscriptLifecycleStore`
owned by the administrative composition. It is not embedded in, returned by or
type-compatible with `relay.Store`. The port exposes only closed operations to:

1. inspect due or explicitly requested lifecycle state;
2. reserve one immutable operation and intent digest;
3. bind verified export evidence when required;
4. persist the lifecycle marker and unsigned administrative receipt preimage;
5. attach the exact external signature idempotently;
6. remove the authorized payload set once;
7. record backup-deletion evidence and complete the operation;
8. inspect/recover one operation by opaque ID.

The ordinary relay runtime receives only an admission/readiness projection that
can fence append and streams. It receives no lifecycle mutation handle. Public
HTTP/SSE routes, session credentials and channel publish/replay/watch grants
cannot invoke the administrative port.

## Operation identity and intent

Every operation has one UUIDv7 `operation_id` and one canonical intent binding:

- tenant, internal channel ID and transcript epoch;
- lifecycle action and closed reason code;
- policy ID, epoch and digest;
- exact target: complete transcript or sorted unique server-sequence set;
- current signed high-water receipt reference;
- requested time, requester role and authorizing audit receipt;
- export requirement and expected backup-deletion deadlines.

The domain-separated SHA-256 intent digest is immutable. Reusing an operation ID
with different bytes is a collision. Exact retries inspect and advance the same
operation; they never reserve a replacement or broaden its target.

Selective redaction targets exact accepted server sequences. Whole deletion
targets one complete transcript epoch. Empty, unknown, unsigned, future,
cross-tenant or already removed targets fail before reservation.

## Recoverable destructive saga

The worker advances one operation through closed monotonic states:

```text
reserved -> export_satisfied -> marker_persisted -> receipt_signed
         -> payload_removed -> backups_pending -> completed
```

`export_satisfied` is immediate only when export is `forbidden` or `permitted`
and no export was requested. Required export needs a bounded manifest containing
the candidate high-water, byte count, content digest, destination class and
external custody receipt digest. Paths, endpoints and credentials remain
private and are not lifecycle evidence.

The event database transaction for `marker_persisted` atomically fences the
epoch, stores the append-only lifecycle marker, exact target/digest, previous
state, resulting incomplete/non-active state, unsigned administrative receipt
preimage and operation high-water. It removes no payload.

The external receipt signer signs only that persisted preimage. Selection and
signature attachment use the existing exact-key, idempotent pending-signature
rules. No payload is removed until the signature is durably attached and
locally verified. Permanent signing failure leaves the epoch fenced, preserves
all payload and records a closed incident boundary.

`payload_removed` is one event-database transaction guarded by the operation ID
and signed marker. Redaction removes only the authorized canonical event payload
while retaining the policy-approved integrity minimum and exact sequence/event
digest tombstone. Whole deletion removes transcript payload and ordinary
record-level metadata, retaining only channel/epoch non-reuse state, the signed
deletion receipt and the minimum audit correlation permitted by policy.

Repeated removal is an exact no-op returning the original outcome. A different
target, policy, receipt or high-water conflicts. There is no update, unredact,
undelete, purge-all or force-complete operation.

## Backup deletion and completion

Event, identity and security-audit backups are independent custody domains.
The lifecycle worker cannot claim to delete them transactionally. After primary
payload removal it records one obligation per domain with an exact deadline and
expected policy digest. An accountable backup custodian supplies a canonical
receipt containing backup identity digest, operation ID, deletion time, method
class and closed success/failure outcome.

The public repository and ordinary process logs retain only digests, deadlines
and closed outcomes. Backup paths, provider responses, credentials and account
identities remain in the controlled operator record.

An operation becomes `completed` only after every required deletion receipt is
durable and security-audited. Missed or failed deadlines keep the operation
`backups_pending`, deny new append for the channel and raise a bounded readiness
and incident signal. They never erase the primary signed lifecycle receipt or
silently extend retention.

Backup obligations bind exact backup-generation digests known to contain the
affected data. A custodian either retires the complete generation or proves
through the accepted backup manifest that the affected data is absent. The
worker never performs an unsafe surgical rewrite of a shared backup and never
deletes a generation containing unrelated live data without its own policy and
authority. Such a conflict is a failed obligation requiring incident handling,
not permission to broaden deletion.

Security-audit evidence itself is retained for its separately declared window.
When its deletion receipt becomes due, the evidence needed to prove that
deletion is anchored in the external signed lifecycle receipt and checkpoint,
not recursively retained forever in the database being deleted.

## Scheduling and clock rollback

The worker persists a wall-clock high-water in the event and security-audit
domains. It schedules against UTC milliseconds but treats time as untrusted:

- a wall time below persisted high-water fences lifecycle advancement;
- a jump beyond a closed maximum scan interval processes a bounded page and
  remains unready until the backlog is reconciled;
- restart resumes reserved operations before discovering new due work;
- expiry never releases claims, accepts handoffs or changes protocol ownership;
- operator clock correction cannot move a stored deadline.

Recovery from clock rollback requires a later time at or above high-water or a
separately audited restore procedure. There is no command-line clock override.

## Crash and restore behavior

Every state transition is idempotent on `operation_id` plus intent digest. On
startup the worker reconciles non-completed operations before reporting
lifecycle readiness. It proves the event database state, attached signature,
payload-removal marker, backup obligations and audit receipts agree.

Unknown, reversed, skipped or contradictory state fences the affected channel
and produces a closed incident reason. Recovery cannot delete evidence to make
state agree, lower an epoch, recreate removed payload, select a new signing key
for a persisted preimage or replace an ambiguous operation.

Restore uses RFC-0011 checkpoint/recovery evidence and additionally verifies:

- restored lifecycle high-water is not below the checkpointed high-water;
- no completed operation becomes pending or active again;
- identifier tombstones and successor epoch floors are preserved;
- a restored payload is not re-exposed after a signed removal receipt;
- backup obligations are the union of checkpointed and restored evidence.

If a backup restore resurrects payload removed by a completed operation, the
worker re-removes it under the original operation without emitting a new
receipt and keeps reads fenced until verification completes.

## Read, export and projection behavior

Replay/export responses bind lifecycle, completeness, policy digest, epoch and
the signed marker/deletion receipt reference. Redacted records never return
removed payload bytes. Deleted transcripts return no event records and only the
closed deletion evidence permitted by policy. A lifecycle transition pending
at or before the requested high-water produces an incomplete boundary.

SSE closes before a fenced or non-active boundary and never emits a later
record. Caches and clients must treat lifecycle evidence as authoritative and
cannot reconstruct a final projection from previously cached payload after a
redaction or deletion marker.

Export is a read/evidence operation, not authority to retain data indefinitely.
The export custodian becomes accountable for the exported copy and its own
deletion deadline. Export failure never falls through to destructive work when
the policy requires export.

### Pre-release HTTP/SSE read revision

The current RFC-0004 implementation admits only `active` channels and its
closed transcript page omits lifecycle. That behavior cannot represent the
already accepted RFC-0001 rule that redacted/deleted transcripts remain
inspectable but non-final. RFC-0023 therefore supersedes that part of the
unreleased v1 binding; it is not presented as a backward-compatible addition.

Every transcript page gains required `lifecycle` and `policy_digest` fields.
Non-active pages additionally require the signed
`lifecycle_receipt_reference`. `completeness` is always `incomplete` when
lifecycle is not `active`. Authorization and non-enumeration still precede
lookup, but the application separates read admission from append/watch
admission:

- authorized replay/export may inspect `active`, `redacted` or `deleted`;
- append requires `active` and no pending lifecycle operation;
- watch requires `active`; a lifecycle fence closes an existing stream before
  any later record;
- direct stream admission for a non-active epoch emits no record and closes at
  the lifecycle boundary;
- a deleted epoch accepts replay only from origin, returns no event records and
  binds the deletion receipt; a non-zero cursor cannot assert continuity and
  fails closed;
- selective redaction replays only the contiguous signed prefix before the
  first removed sequence and reports that exact incomplete boundary.

The client page decoder, replay verifier, inspect projection and SSE state
machine must be updated in the later implementation increment. No old page
shape, compatibility media type or route alias is retained because the CLI and
relay executable remain unreleased.

## Roles and audit

The profile names distinct accountable roles:

- tenant policy approver;
- channel lifecycle requester;
- lifecycle authorizer;
- lifecycle worker operator;
- export custodian;
- event, identity and audit backup custodians;
- receipt-signing operator;
- security reviewer and residual-risk acceptor.

One human may hold multiple roles only when the controlled change record says
so. Runtime sessions and protocol participants hold none of these roles.

Security audit uses closed operations/reasons for policy activation, lifecycle
reservation, export verification, marker persistence, signing outcome, primary
removal, backup receipt, completion, deadline miss, clock fence, restore and
incident. Audit records contain digests and opaque references, never removed
payload, credentials, private paths or arbitrary provider errors.

## Failure and safety properties

- missing policy denies first append;
- overdue or lifecycle-pending epochs deny append and terminate live delivery;
- no destructive action occurs before durable authorization, marker and
  signature;
- ambiguous outcomes reconcile by operation ID and never create a replacement;
- partial failure can only advance to a more fenced state;
- payload absence never restores completeness or implies it was never accepted;
- backup deletion is evidenced per custody domain, never assumed;
- no failure retries a protocol event or changes project ownership;
- removed bytes never enter errors, metrics, logs, audit or public evidence.

## Compatibility

RFC-0001 lifecycle/completeness semantics remain unchanged and no public
destructive route is added. The unreleased RFC-0004 transcript/read
implementation changes incompatibly as described above: lifecycle becomes
explicit and non-active reads become representable. This requires coordinated
relay and client updates before either executable may be released; silent
dual-shape decoding is forbidden.

`relay.Store` remains source-compatible and authority-neutral. SQLite gains a
separate adapter-owned administrative port. Memory and JetStream adapters do
not claim lifecycle conformance from this RFC.

## Qualification plan

Acceptance requires a later implementation plan covering:

- closed policy and lifecycle schemas plus canonical vectors;
- missing/default/infinite/rollback policy rejection;
- separate-port compile-time and credential-boundary tests;
- redaction/deletion marker and receipt byte identity;
- no removal before signature and exact retry after lost acknowledgement;
- crash injection at every saga state;
- clock rollback/jump and overdue admission fencing;
- selective redaction, whole deletion and projection-ineligibility;
- successor epoch and identifier non-reuse;
- backup receipt success, failure, deadline and restore resurrection;
- cross-database recovery with RFC-0011 checkpoints;
- redaction of payload, path, credential and provider detail;
- deterministic replay/export behavior after each lifecycle state;
- exact revised HTTP page/SSE shapes and old-shape rejection in both relay and
  client.

Destructive tests use generated synthetic data in disposable directories only.
No implementation test may target an operator or user path.

## Rollout and rollback

Rollout is disabled by default and proceeds as separately reviewed schema/port,
SQLite operation, worker/saga, recovery and executable-composition increments.
The relay process cannot admit events until all are merged and qualified.

Before any real destructive execution, an immutable implementation record,
synthetic operator runbook, backup-custody evidence and explicit owner approval
are required. Rollback may disable scheduling and keep admission fenced; it
cannot reverse a signed redaction/deletion, restore removed payload to public
reads, lower an epoch or erase lifecycle evidence.

## Alternatives rejected

### Add delete methods to `relay.Store`

Rejected because ordinary append/replay authority must not acquire
administrative destruction capability.

### Use database TTL or JetStream retention

Rejected because expiry without signed lifecycle evidence makes deletion look
like missing or never-accepted history and cannot coordinate backup custody.

### Delete first and audit afterward

Rejected because signer/audit failure would leave irreversible action without
durable authorization or independently verifiable evidence.

### Keep every payload forever for auditability

Rejected because it violates finite accountable retention and conflates
integrity evidence with indefinite content storage.

### Pretend cross-database deletion is atomic

Rejected because event, identity, audit, signer, export and backup domains have
independent failure and custody boundaries. The explicit monotonic saga is the
honest contract.

## Open questions

None. Policy values remain adopter-owned inputs, but their closed shape,
authority, evidence and failure semantics are frozen here.
