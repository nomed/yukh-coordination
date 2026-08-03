# RFC-0006: JetStream adapter layout

- Status: Accepted
- Author: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #5
- Governing architecture: RFC-0001, RFC-0002, RFC-0003 and RFC-0005

## Decision requested

Freeze the first NATS JetStream layout that can implement the neutral `Store`
and live-notification ports without splitting one Yukh append across a KV
bucket and a stream.

Acceptance authorizes adapter implementation and repository qualification only.
It does not authorize a NATS deployment, production topology, public admission
or production-readiness claim.

The project owner accepted this layout on 2026-08-03 after review in PR #24.

## Core decision

JetStream stores one append-only command log per tenant subject inside one
adapter-owned stream. Every state change for a tenant is serialized with
JetStream optimistic concurrency using `Nats-Expected-Last-Subject-Sequence`.

KV is not used anywhere in the authoritative read or write path. JetStream is
used solely as a linearizable tenant command log; all indexes and current state
are deterministic reducer views of that log.

The stream is named `YUKH_COORDINATION_V1` and accepts only:

```text
yukh.coordination.v1.tenant.{tenant_token}.log
```

`tenant_token` is lowercase base32 without padding of SHA-256 over the exact
UTF-8 tenant ID. It is routing material only. The authoritative tenant ID
remains inside each canonical command and must hash back to the subject token.
Raw tenant, channel, participant and event identifiers never appear in NATS
subjects, stream names, consumer names or headers.

One shared stream does not create a shared ordering contract. The exact tenant
subject is the optimistic-concurrency domain; Yukh still promises no order
across tenants or channels.

## Why a command log

The Store transaction includes immutable channel registration, event-ID
uniqueness across transcript epochs, stateful admission, per-transcript sequence
allocation and accepted-record persistence. JetStream KV CAS and stream publish
are separate operations and cannot jointly provide that transaction.

For each mutation the adapter:

1. reads and reduces the exact tenant subject through its current last stream
   sequence;
2. evaluates the Store operation and `AdmissionView` against that state;
3. prepares the next deterministic command;
4. publishes it synchronously with the last observed tenant-subject sequence as
   the expected value;
5. on optimistic conflict, discards the candidate, reloads and retries within a
   bounded attempt count;
6. on an ambiguous acknowledgement, reloads and resolves by immutable channel,
   event or receipt identity before returning success or
   `ErrCommitIndeterminate`.

The preparation and admission callbacks may therefore run again, as already
permitted by RFC-0003. Network calls and signing remain forbidden inside them.

## Two sequence domains

JetStream stream sequence is an adapter revision used only for optimistic
concurrency, recovery and filtered consumption. It never appears in an event,
receipt, public cursor or projection.

Yukh `AcceptedRecord.Sequence` remains contiguous from 1 within
`(tenant_id, channel_id, transcript_epoch)`. The reducer derives the next Yukh
sequence from the accepted tenant log before calling `PrepareRecord`.

## Closed command envelope

Every message body is canonical JSON with exactly:

```json
{
  "command_id": "01989f0e-56b7-7e01-915e-a7748f7f6280",
  "command_type": "record_appended",
  "command_version": "1",
  "payload": {},
  "tenant_id": "tenant:example"
}
```

The closed command types are:

- `channel_created`: complete immutable `relay.Channel` material;
- `record_appended`: complete unsigned `relay.AcceptedRecord` material;
- `signature_attached`: channel key, receipt ID, exact preimage digest and raw
  signature bytes.

Binary fields use base64url without padding. Numeric values are bounded JSON
safe integers. The adapter validates canonical bytes, closed fields, command
version, subject-token binding and all reducer invariants during every replay.
Unknown or malformed commands fail the tenant closed; they are never skipped.

`record_appended` is the atomic Yukh acceptance point. Signature attachment is
a later idempotent command because JetStream messages are immutable, matching
the existing signer failure-domain separation. Replay stops at an unsigned
record exactly as it does for SQLite.

## Idempotency and publication ambiguity

`Nats-Msg-Id` deduplication is not a correctness primitive for Yukh. NATS
compares the identifier, not the body, and retains identifiers only for the
configured duplicate window. A same-ID/different-byte Yukh event must remain a
collision forever within retained history.

The reducer therefore owns idempotency using canonical event bytes and event
identity. A retry after a lost publish acknowledgement reloads the log:

- an exact existing event returns the original record;
- the same event ID with changed bytes returns `ErrEventIDCollision`;
- an exact signature attachment returns the signed record;
- a changed signature or preimage returns `ErrSignatureCollision`;
- no provable outcome returns `ErrCommitIndeterminate`.

Client-generated JetStream message IDs may be used only as bounded operational
telemetry and cannot alter these outcomes.

## Stream configuration boundary

Qualification requires the existing stream configuration to match exactly:

- file storage and limits retention;
- discard-new policy;
- acknowledgements enabled;
- no maximum age, message count or byte limit that can silently remove retained
  protocol history;
- message deletion and purge denied;
- rollups disabled;
- atomic batch publishing disabled and not required: one Yukh transition is one
  canonical command publication;
- one subject pattern, no mirrors, sources or republish;
- maximum message size large enough for the bounded command envelope;
- replica count supplied explicitly by environment configuration.

The adapter may create the stream only when explicitly configured to bootstrap.
Otherwise a missing or mismatched stream fails closed. Qualification may use
one replica; production replica count, placement, accounts, credentials,
encryption, storage capacity and disaster recovery remain deployment decisions
and are not defaulted by this RFC.

## Reads and reducer integrity

Lookup and bounded replay reduce only the authenticated tenant subject and then
apply channel/transcript predicates in memory. They return the same defensive
copies and error vocabulary as the memory and SQLite adapters.

The reducer proves on every command:

- immutable tenant/channel/URI mapping;
- one event ID per tenant/channel across epochs;
- gap-free transcript sequences;
- event digest and prepared-record bindings;
- unique receipt identity;
- signature attachment to the exact stored preimage;
- command and subject tenant equality.

Snapshots and rollups are excluded from the first adapter. They are
optimizations requiring separate integrity and retention design; replaying the
complete retained command log is the qualification baseline.

## Live notification

The adapter also implements the application `SubscriptionSource`. It creates a
bounded ephemeral filtered consumer for the exact tenant subject before the
application performs its first durable read. Commands are wake-up hints only;
the application rereads authoritative records from the Store.

Notifications may coalesce and may be spurious across channels in the same
tenant. Consumer setup must complete before `Subscribe` returns. Cancellation
deletes the ephemeral consumer. Consumer failure closes the subscription so the
HTTP stream reconnects without advancing its last delivered Yukh sequence.

Core NATS delivery alone is insufficient because it is at-most-once; the live
wake-up path uses JetStream consumption and the durable read closes any
notification duplication.

## Qualification evidence

Tests run against a real disposable `nats-server` with JetStream enabled and
must cover:

- memory/SQLite Store contract parity;
- concurrent writers with optimistic conflicts and gap-free Yukh sequences;
- exact retry and same-ID/different-byte collision beyond message dedup logic;
- preparation failure with no command committed;
- lost-ack reconciliation for append and signature attachment;
- process reconnect and complete reducer rebuild;
- unsigned boundary followed by signature recovery;
- tenant subject isolation and hostile token/payload mismatch;
- malformed, unknown-version and invariant-breaking command failure;
- subscribe-before-read interleavings and consumer cancellation;
- mismatched stream configuration refusal.

The test server binary is a development dependency downloaded or supplied by
CI; it is not committed to the repository.

## Alternatives rejected

### KV for indexes plus a record stream

Rejected because KV CAS and stream publication do not form the single atomic
acceptance operation required by the Store contract.

JetStream 2.12 atomic batch publication does not change this choice: it can
atomically add multiple messages to one stream, but it does not create a
transaction between a separate KV bucket and an application stream. The first
adapter needs only one command message per transition.

### One stream or subject per channel

Rejected because event-ID uniqueness and immutable URI mapping span transcript
epochs, while tenant administration must not become a cross-stream transaction.

### Global stream-sequence receipts

Rejected because unrelated tenants and channels would create gaps and expose
adapter topology through the public Yukh cursor.

### JetStream message deduplication as event idempotency

Rejected because deduplication is ID-only and window-bounded, whereas Yukh must
compare exact canonical bytes for the retained lifetime.

## Primary references

- [NATS JetStream headers](https://docs.nats.io/nats-concepts/jetstream/headers)
- [JetStream model and message deduplication](https://docs.nats.io/using-nats/developer/develop_jetstream/model_deep_dive)
- [JetStream streams and retention](https://docs.nats.io/nats-concepts/jetstream/streams)
- [JetStream consumers](https://docs.nats.io/nats-concepts/jetstream/consumers)
