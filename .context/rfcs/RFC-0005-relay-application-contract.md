# RFC-0005: Relay application contract

- Status: Proposed
- Author: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #5
- Governing architecture: RFC-0001, RFC-0002, RFC-0003 and RFC-0004

## Decision requested

Freeze the transport-neutral application contract between the HTTP/SSE edge,
canonical protocol validation, durable append, immutable channel metadata and
live delivery. This closes serialization and race boundaries left deliberately
open by RFC-0004 before application code is written.

Acceptance authorizes implementation and repository qualification only. It
does not authorize a provider, executable server, deployment or production use.

## Boundary

The application service orchestrates already-authenticated and authorized
requests. It does not authenticate, decide policy, own durable storage, sign
with key material, project authoritative work state or expose broker concepts.

Its dependencies remain ports:

- the accepted schema set and JCS canonicalizer;
- immutable channel metadata lookup;
- the signed append service from the relay core;
- a durable ordered record reader;
- a live-change subscription whose notifications are hints, never data.

SQLite, JetStream, Matrix and identity providers remain adapters outside this
service.

## Admitted identity and authorization

The edge passes a closed admitted context containing tenant, principal,
participant instance, numeric session epoch, channel key and the canonical ACL
decision binding. The binding also exposes, as validated structured values,
`acl_policy_version`, `acl_policy_digest` and `acl_decision_receipt_id`.

The application rejects an incomplete context. It never parses forwarded
identity or accepts a tenant, principal, policy or channel binding from the
event body.

## Immutable channel lookup

The persistence port exposes exact lookup by `(tenant_id, channel_id,
transcript_epoch)` and returns:

- the registered channel URI;
- the exact canonical channel-metadata bytes;
- their frozen domain-separated digest;
- transcript lifecycle and completeness inputs needed for replay.

Channel creation validates and persists these values atomically. Lookup cannot
fall back to an alias or a different epoch. Existing adapters are migrated in
the same implementation increment; an absent metadata record fails closed.

## Event admission

For append, the application performs this order after admission:

1. enforce valid UTF-8, the 65,536-byte limit and one JSON value;
2. reject duplicate keys, excess nesting and every JSON number at any depth;
3. require byte equality with RFC 8785 JCS output;
4. validate the accepted v0.1 envelope and selected payload schema;
5. apply the frozen RFC-0001 semantic and reference rules;
6. require the event channel URI to equal immutable channel metadata;
7. call the signed append service with the exact accepted bytes.

Validation uses the repository schema sources directly; no copied schema tree
is introduced under `internal/`. Schema compilation is fixed at application
construction and fails closed.

## Receipt construction

Before append, the service selects a signing key through the existing append
service. After sequence allocation it builds the exact RFC-0001 unsigned
receipt with:

- a fresh UUIDv7 receipt ID;
- UTC receive time truncated to milliseconds;
- decimal route transcript epoch and numeric session epoch;
- cursor equal to the decimal server sequence for HTTP binding v1;
- event identity and digest from validated canonical bytes;
- identity, channel-metadata and ACL fields only from admitted server state;
- `append_outcome: "appended"` even when an exact retry is returned to HTTP;
- the selected `key_id` and `signature_algorithm`.

The stored preimage is JCS of the closed receipt with `signature` absent. After
the raw Ed25519 signature is durably attached, the application emits JCS of the
same object plus base64url-without-padding `signature`. It never reconstructs
mutable receipt fields on retry.

## Canonical record and bounded replay

One canonical record has exactly two members:

```json
{"event":{...},"receipt":{...}}
```

`event` and `receipt` embed their exact parsed canonical representations; they
are not JSON strings. The whole record is JCS and therefore one line.

A successful bounded page is JCS of this closed object:

```json
{
  "after": 0,
  "channel_id": "channel:release",
  "channel_uri": "https://coord.example/channels/project-release",
  "completeness": "complete",
  "high_water_sequence": 2,
  "records": [],
  "specversion": "0.1",
  "transcript_epoch": 0
}
```

`after` is the requested exclusive cursor. `high_water_sequence` is the last
contiguous signed sequence emitted, or `after` for an empty page. An incomplete
page additionally contains `boundary_sequence`, the first unsigned sequence,
and stops before it. `boundary_sequence` is absent for a complete page. The
page never includes tenant identity or internal signer diagnostics.

The service verifies sequence continuity, event digest, receipt/event binding
and the durable signature presence before serialization. Signature
cryptographic verification belongs to the later verifier/qualification layer;
absence or structural inconsistency already forms an incomplete boundary.

## Race-free replay to live

Live subscription carries only a coalescing “state may have advanced” signal.
The durable store remains the sole source of record bytes.

The application establishes delivery in this order:

1. subscribe for changes after the admitted cursor;
2. read and emit every contiguous durable signed record after that cursor;
3. when caught up, wait for a notification;
4. read durably again from the last emitted sequence;
5. repeat until cancellation, boundary, revocation or adapter failure.

The subscription contract guarantees that, after `Subscribe` returns, a later
successful append eventually signals. An append completed before that return
is visible to the subsequent durable read. Signals may coalesce and may be
spurious; record delivery may not depend on their count. This ordering closes
the snapshot/subscription gap without putting event bodies on an in-memory bus.

Per-subscriber queues are bounded to one coalesced signal. A blocked consumer
cannot block append. Adapter failure closes the stream with a retryable error;
it never advances the client cursor.

## Qualification evidence

Implementation must prove:

- all positive and negative event fixtures agree with the existing independent
  conformance runners;
- non-canonical, duplicate-key, numeric and wrong-channel input never appends;
- receipt preimage and signed receipt match the published canonical vectors;
- exact retry returns byte-identical signed receipt output;
- pages are byte-deterministic across page boundaries;
- unsigned sequence `n` prevents delivery of `n` and every later record;
- append in each subscribe/read interleaving is delivered without a gap;
- coalesced and spurious notifications produce neither loss nor reordering;
- cancellation and slow-consumer pressure do not block append or leak goroutines.

## Alternatives rejected

### Serialize pages ad hoc in the HTTP handler

Rejected because transport would own protocol bytes and replay rules, making
other bindings diverge.

### Put complete records on an in-process publish/subscribe bus

Rejected because the bus would become a second, non-durable transcript and
could diverge from committed storage.

### Read first and subscribe afterward

Rejected because an append between those operations creates a lost-wakeup gap.

### Make JetStream the application contract

Rejected because it would leak the selected durability adapter into the core
and prevent SQLite qualification or future replacement.
