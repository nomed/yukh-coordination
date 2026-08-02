# RFC-0001: Yukh Coordination Protocol v0.1

- Status: Draft
- Governing issue: #2
- Authors: Nomed with protocol-design review
- Last updated: 2026-08-02

## Decision requested

Freeze the authority-neutral event envelope, relay-local ordering, deterministic projection, claim-conflict, evidence, handoff, error, canonicalization, and compatibility semantics required before conformance work begins.

This RFC does not authorize relay or CLI implementation.

## Decision status and qualification boundary

The project owner selected the v0.1 design decisions expressed below. They are
approved inputs, not an accepted compatibility commitment. This RFC remains
**Draft** until issue #4 supplies byte-exact fixtures, signed-receipt vectors,
projection vectors, published digests, and two independent cross-runtime
conformance results.

## Normative language

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are interpreted as described by RFC 2119 and RFC 8174.

## Boundary

The protocol records attributed coordination statements. It does not grant execution authority, elect an owner, accept work, infer reviewer independence, or mark project state complete.

A `claim` is an observable claim assertion. A `handoff_accept` is an attributed acceptance statement. Any authoritative ownership projection MUST reference an external policy decision or receipt and identify that policy.

## Event and receipt

The immutable client event is separate from the relay receipt. Relay metadata MUST NOT be inserted into or rewrite accepted event bytes.

Every event contains:

| Field | Rule |
|---|---|
| `specversion` | REQUIRED; exact `0.1` for this draft |
| `id` | REQUIRED canonical lowercase UUIDv7; idempotency key within one immutable tenant/channel mapping |
| `type` | REQUIRED closed v0.1 signal enum |
| `channel` | REQUIRED absolute URI; exact string identity |
| `source` | REQUIRED absolute URI for the producing client/session; not authority |
| `participant` | REQUIRED asserted participant ID/kind; authenticated binding is supplied by the receipt |
| `work` | REQUIRED for work signals; forbidden for channel-only signals |
| `time` | REQUIRED UTC RFC 3339 with millisecond precision; informational only |
| `correlation_id` | REQUIRED UUIDv7 for work, question, review, and handoff families |
| `causation_id` | REQUIRED UUIDv7 for every non-root event and references an already accepted event in the same tenant/channel |
| `data` | REQUIRED object validated by the signal schema |
| `evidence` | REQUIRED array, including when empty |
| `extensions` | REQUIRED object, including when empty |

Unknown top-level fields, unknown core event types, duplicate keys, and `null` where not explicitly allowed MUST be rejected.

Canonical events MUST be at most 65,536 UTF-8 bytes. URIs are at most
2,048 UTF-8 bytes; participant IDs and displays are at most 256 and 128
characters; prose is at most 4,096 characters; arrays contain at most 32 items;
objects contain at most 64 properties; extensions contain at most 32 keys; JSON
nesting depth is at most 16. Client events and extensions contain no JSON number
at any depth. Numeric concepts in event payloads use bounded decimal strings.

The relay receipt contains at least:

```json
{
  "event_id": "01989f0e-56b7-7e01-915e-a7748f7f6280",
  "tenant_id": "tenant:example",
  "channel_id": "channel:project-release",
  "principal_id": "principal:alice",
  "participant_id": "session:wave-2",
  "participant_instance_id": "01989f0e-56b7-7e01-915e-a7748f7f6281",
  "session_epoch": 1,
  "cursor": "opaque-relay-cursor",
  "sequence": 42,
  "accepted_at": "2026-08-02T16:00:00.123Z",
  "event_digest": "sha-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "key_id": "relay-key-2026-08",
  "signature_algorithm": "ed25519",
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

`tenant_id`, `channel_id`, `principal_id`, `cursor`, `sequence`, and `accepted_at` are relay-derived. Clients MUST NOT choose them through the event body.

The relay also issues `participant_instance_id` and `session_epoch` so a reused
participant label cannot impersonate an earlier process. One authenticated
tenant maps an exact channel URI to one immutable `channel_id`; rebinding is
forbidden and migration creates a new mapping.

Receipts are at most 16,384 UTF-8 bytes and contain `key_id`,
`signature_algorithm: "ed25519"`, and a base64url-no-padding signature. The
signature covers JCS of the receipt with `signature` omitted, domain-separated
by `yukh-coordination-receipt-v0.1` followed by a NUL byte. The signing key MUST
remain outside the event database and its recovery domain. A receipt authenticates
relay admission and binding, not work authorization or evidence truth.

## Signal families

The v0.1 core types are:

- advisory presence: `join`, `presence`, `leave`;
- work assertions: `claim`, `progress`, `release`;
- conversation: `question`, `answer`;
- review: `review_request`, `verdict`;
- handoff: `handoff_offer`, `handoff_accept`.
- evidence reporting: `evidence_verification`.

### Presence

Presence is advisory and ephemeral. Durable `join`, `presence`, and `leave` events are historical observations; replay MUST NOT reconstruct current availability from an expired observation. Presence MUST NOT change a claim, ACL, or authority decision.

### Claim assertions

A claim payload contains a stable `claim_id`, decimal-string generation,
bounded `scope`, bounded `boundary`, optional immutable `governance_ref`, and an
exact sorted `expected_active_claims` set. Append is compare-and-set against that
relay projection. A stale set is rejected; CAS does not elect an authority.

Concurrent active claims over the same exact work identity MUST project `conflicting` with every contender. Arrival order, event time, UUID order, presence, or relay sequence MUST NOT select a winner. Resolution requires a referenced external authority decision or an explicit later protocol assertion that does not misrepresent itself as authoritative.

Projection states are at least `unclaimed`, `claimed`, `conflicting`, `handoff_offered`, and `released`. `claimed` means one observable active assertion, not accepted authority.

Release targets one claim ID and generation and causally references its last
lifecycle event. Reuse of a `(claim_id, generation)` is forbidden. Leave,
expiry, staleness, timeout, or session loss never implies release.

### Questions and answers

An answer MUST reference an existing question in the same channel and retain its correlation ID. Multiple answers are preserved. No answer overwrites another or inherits the requester's authority.

### Reviews and verdicts

A review request freezes its criteria and evidence-set digest. A verdict references one exact review request and evidence set. `pass`, `fail`, and `inconclusive` are attributed reviewer statements; the relay MUST NOT infer independence, acceptance, or a project transition.

### Handoff

A handoff offer binds:

- `handoff_id`;
- source `claim_id` and claim generation;
- exact authenticated intended recipient;
- channel and work identity;
- boundary digest;
- evidence-set digest;
- unresolved risks and next action.

Acceptance MUST reference the exact offer and match its authenticated recipient. An acceptance after the source claim is released, superseded, or changed is invalid. Competing acceptances project conflict and never elect a recipient. Handoff remains an observable proposed transfer unless an external authority receipt is referenced.

## Evidence

Evidence contains `uri`, `media_type`, and at least one of an immutable provider revision or a SHA-256 digest over exact representation bytes. v0.1 supports SHA-256 only.

A digest proves content identity, not truth, freshness, provenance, CI status, reviewer independence, or authorization. The core relay MUST NOT fetch arbitrary evidence URIs. Verification is performed by a separately authorized client/verifier and reported as new evidence.

`evidence_verification` references one exact evidence descriptor digest and
reports `verified`, `mismatch`, `unavailable`, or `inconclusive`, plus verifier,
method, and verification time. It is an attributed observation and never
rewrites the descriptor or grants authority.

Credentials, secret query parameters, private prompts, inline evidence bodies, and unrestricted logs are forbidden.

## Ordering, delivery, and replay

- Event time and UUID order are never authoritative ordering.
- Causation defines a partial order.
- The MVP relay assigns a monotonically increasing sequence per tenant/channel log.
- No global or cross-relay order is promised.
- A missing causal predecessor is rejected with `UNRESOLVED_CAUSATION`; it is never appended, deferred, or silently projected.
- Replay from origin and replay across arbitrary page boundaries MUST produce the same derived state and diagnostics.
- Pagination cursors are tenant/channel-scoped and opaque or integrity-protected.

## Idempotency and collisions

`(tenant, immutable channel mapping, event.id)` is unique. Resubmission of identical JCS canonical bytes returns the original signed receipt without a second append. The same ID with different canonical bytes is rejected and security-audited as `ID_COLLISION`. Similar payloads with distinct IDs remain distinct events.

Event append, principal binding, channel sequence assignment, and idempotency record MUST commit atomically before success is acknowledged.

## Canonical bytes

Canonicalization uses RFC 8785 JCS over a narrower domain:

- UTF-8, no BOM;
- top-level JSON object;
- duplicate keys and unpaired surrogates rejected;
- Unicode preserved without normalization;
- numbers prohibited in client events unless a later schema explicitly permits safe integers;
- timestamps and UUIDs use exact lexical forms;
- no fields excluded from the event digest.

The digest is `sha-256:<lowercase SHA-256 hex of JCS(event)>`. All fields,
including `id`, participate. The relay stores the canonical accepted bytes;
parsed-object equality is not idempotency. Event signatures, if later added,
are detached to avoid self-reference.

## Compatibility

Wire media type is `application/yukh-coordination+json;version=0.1`. Version negotiation selects one exact mutually supported version; downgrade is never implicit.

Stored events retain original bytes and version. Migrations create derived projections and never rewrite history. Reverse-DNS extension keys may be preserved but MUST NOT change core semantics.

Removing fields, changing requiredness, canonicalization, projection semantics, rejection behavior, or authority meaning requires a major version.

## Error contract

Errors use `application/problem+json` and a stable code. The initial codes include:

`INVALID_ENVELOPE`, `UNSUPPORTED_VERSION`, `INVALID_EVENT_TYPE`, `INVALID_PAYLOAD`, `INVALID_REFERENCE`, `CROSS_CHANNEL_REFERENCE`, `UNRESOLVED_CAUSATION`, `CAUSAL_CYCLE`, `ID_COLLISION`, `CLAIM_CONFLICT`, `INVALID_CLAIM_TRANSITION`, `INVALID_HANDOFF_PARTICIPANT`, `ALREADY_ACCEPTED_HANDOFF`, `EVIDENCE_INTEGRITY_REQUIRED`, `ACCESS_DENIED`, and `TEMPORARILY_UNAVAILABLE`.

Rejected events are not protocol events. Security-relevant rejection metadata belongs to a separate restricted audit log.

Problem documents are at most 16,384 UTF-8 bytes. Unauthorized callers receive
one non-enumerating `ACCESS_DENIED` shape that does not reveal tenant, channel,
participant, event, claim, or evidence existence. `detail`, `event_id`, and
internal diagnostics are absent unless disclosure is authorized. A bounded
opaque `trace_id` supports restricted audit correlation.

## Transcript completeness and retention

A transcript is `complete` only when replay starts at the log origin, ends at a
signed relay high-water receipt, has a contiguous verified sequence, validates
all receipt signatures and event digests, and resolves all references. Any
omission, unverifiable receipt, mismatch, missing predecessor, or unknown
version makes it `incomplete`. Incomplete transcripts may be inspected but MUST
NOT assert final claim, handoff, review, or presence projections.

There is no default retention period. A relay MUST refuse channel creation
until an accountable retention policy is supplied and bound into channel
metadata. Redaction or deletion makes affected transcripts incomplete; it never
silently rewrites accepted bytes or preserves a false completeness claim.

## Required conformance evidence

Acceptance requires schemas, exact canonical byte vectors, SHA-256 manifests, positive/negative fixtures for every signal, and deterministic projection fixtures.

The adversarial transcript MUST cover spoofed participant data, concurrent claims, exact duplicates, same-ID/different-byte collision, reordered client time, expired presence, late and multiple handoff acceptance, changed/unavailable evidence, wrong evidence digest, arbitrary page boundaries, and denied cross-tenant access without existence leakage.

Two independent implementations from different runtime families MUST produce byte-identical canonical bytes, derived state, and diagnostics.

## Handoff CAS and successor ownership

`handoff_accept` is compare-and-set over the exact offer event, source claim
generation, authenticated intended `participant_instance_id`, and unchanged
active source claim. Changed or released state is rejected. Acceptance closes
the offer but neither transfers nor creates ownership. The recipient publishes
a separate `claim` with a new claim ID/generation and
`predecessor_handoff_event`; normal claim CAS and external policy apply. The
intermediate projection is `handoff_accepted_unclaimed`.

## Remaining qualification evidence

Issue #4 must prove all closed schemas, limits, nesting/number rejection,
canonical bytes, signed receipts, claim conflict/release generations, handoff
CAS, evidence verification, transcript completeness, retention binding,
non-enumerating errors, and cross-runtime equivalence. These are evidence gates,
not remaining implementation discretion.

Federation, portable cursors, automatic leases, winner election, retention
policy selection, redaction mechanisms, and reviewer-independence inference are
excluded from v0.1.
