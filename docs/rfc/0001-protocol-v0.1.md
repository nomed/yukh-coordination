# RFC-0001: Yukh Coordination Protocol v0.1

- Status: Draft
- Governing issue: #2
- Authors: Nomed with protocol-design review
- Last updated: 2026-08-02

## Decision requested

Freeze the authority-neutral event envelope, relay-local ordering, deterministic projection, claim-conflict, evidence, handoff, error, canonicalization, and compatibility semantics required before conformance work begins.

This RFC does not authorize relay or CLI implementation.

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
| `id` | REQUIRED canonical lowercase UUIDv7; idempotency key within one tenant |
| `type` | REQUIRED closed v0.1 signal enum |
| `channel` | REQUIRED absolute URI; exact string identity |
| `source` | REQUIRED absolute URI for the producing client/session; not authority |
| `participant` | REQUIRED asserted participant ID/kind; authenticated binding is supplied by the receipt |
| `work` | REQUIRED for work signals; forbidden for channel-only signals |
| `time` | REQUIRED UTC RFC 3339 with millisecond precision; informational only |
| `correlation_id` | REQUIRED for question, review, claim, and handoff families |
| `causation_id` | REQUIRED except for a correlation root |
| `data` | REQUIRED object validated by the signal schema |
| `evidence` | REQUIRED array, including when empty |
| `extensions` | REQUIRED object, including when empty |

Unknown top-level fields, unknown core event types, duplicate keys, and `null` where not explicitly allowed MUST be rejected.

The relay receipt contains at least:

```json
{
  "event_id": "01989f0e-56b7-7e01-915e-a7748f7f6280",
  "tenant_id": "tenant:example",
  "channel_id": "channel:project-release",
  "principal_id": "principal:alice",
  "participant_id": "session:wave-2",
  "cursor": "opaque-relay-cursor",
  "sequence": 42,
  "accepted_at": "2026-08-02T16:00:00.123Z",
  "event_digest": "sha-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

`tenant_id`, `channel_id`, `principal_id`, `cursor`, `sequence`, and `accepted_at` are relay-derived. Clients MUST NOT choose them through the event body.

## Signal families

The v0.1 core types are:

- advisory presence: `join`, `presence`, `leave`;
- work assertions: `claim`, `progress`, `release`;
- conversation: `question`, `answer`;
- review: `review_request`, `verdict`;
- handoff: `handoff_offer`, `handoff_accept`.

### Presence

Presence is advisory and ephemeral. Durable `join`, `presence`, and `leave` events are historical observations; replay MUST NOT reconstruct current availability from an expired observation. Presence MUST NOT change a claim, ACL, or authority decision.

### Claim assertions

A claim payload contains a stable `claim_id`, bounded `scope`, bounded `boundary`, and optional immutable `governance_ref`.

Concurrent active claims over the same exact work identity MUST project `conflicting` with every contender. Arrival order, event time, UUID order, presence, or relay sequence MUST NOT select a winner. Resolution requires a referenced external authority decision or an explicit later protocol assertion that does not misrepresent itself as authoritative.

Projection states are at least `unclaimed`, `claimed`, `conflicting`, `handoff_offered`, and `released`. `claimed` means one observable active assertion, not accepted authority.

Release targets one claim generation. Leave, expiry, staleness, timeout, or session loss never implies release.

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

Credentials, secret query parameters, private prompts, inline evidence bodies, and unrestricted logs are forbidden.

## Ordering, delivery, and replay

- Event time and UUID order are never authoritative ordering.
- Causation defines a partial order.
- The MVP relay assigns a monotonically increasing sequence per tenant/channel log.
- No global or cross-relay order is promised.
- A missing causal predecessor leaves an event unapplied with `UNRESOLVED_CAUSATION`; it is never silently projected.
- Replay from origin and replay across arbitrary page boundaries MUST produce the same derived state and diagnostics.
- Pagination cursors are tenant/channel-scoped and opaque or integrity-protected.

## Idempotency and collisions

`(tenant, event.id)` is unique. Resubmission of identical canonical bytes returns the original receipt without a second append. The same ID with different canonical bytes is rejected and security-audited as `ID_COLLISION`. Similar payloads with distinct IDs remain distinct events.

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

The digest is `sha-256:<lowercase SHA-256 hex of JCS(event)>`. Any future signature is detached to avoid self-reference.

## Compatibility

Wire media type is `application/yukh-coordination+json;version=0.1`. Version negotiation selects one exact mutually supported version; downgrade is never implicit.

Stored events retain original bytes and version. Migrations create derived projections and never rewrite history. Reverse-DNS extension keys may be preserved but MUST NOT change core semantics.

Removing fields, changing requiredness, canonicalization, projection semantics, rejection behavior, or authority meaning requires a major version.

## Error contract

Errors use `application/problem+json` and a stable code. The initial codes include:

`INVALID_ENVELOPE`, `UNSUPPORTED_VERSION`, `INVALID_EVENT_TYPE`, `INVALID_PAYLOAD`, `INVALID_REFERENCE`, `CROSS_CHANNEL_REFERENCE`, `UNRESOLVED_CAUSATION`, `CAUSAL_CYCLE`, `ID_COLLISION`, `CLAIM_CONFLICT`, `INVALID_CLAIM_TRANSITION`, `INVALID_HANDOFF_PARTICIPANT`, `ALREADY_ACCEPTED_HANDOFF`, `EVIDENCE_INTEGRITY_REQUIRED`, `ACCESS_DENIED`, and `TEMPORARILY_UNAVAILABLE`.

Rejected events are not protocol events. Security-relevant rejection metadata belongs to a separate restricted audit log.

## Required conformance evidence

Acceptance requires schemas, exact canonical byte vectors, SHA-256 manifests, positive/negative fixtures for every signal, and deterministic projection fixtures.

The adversarial transcript MUST cover spoofed participant data, concurrent claims, exact duplicates, same-ID/different-byte collision, reordered client time, expired presence, late and multiple handoff acceptance, changed/unavailable evidence, wrong evidence digest, arbitrary page boundaries, and denied cross-tenant access without existence leakage.

Two independent implementations from different runtime families MUST produce byte-identical canonical bytes, derived state, and diagnostics.

## Open decisions blocking acceptance

1. Mandatory UUIDv7 versus opaque producer IDs.
2. Exact URI identity versus registered opaque work identifiers.
3. Store-and-defer versus reject for missing causal predecessors.
4. Whether handoff acceptance derives a successor observable claim or requires a new claim event.
5. Whether claim preconditions are advisory or a relay compare-and-set condition.
6. Retention/redaction semantics and their effect on verifiable transcripts.
7. Receipt signing boundary and key ownership, aligned with #3.

Federation, portable cursors, automatic leases, winner election, and reviewer-independence inference are explicitly excluded from v0.1.
