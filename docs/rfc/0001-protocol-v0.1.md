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

A `claim` is an observable assertion and a `handoff_accept` is an attributed
acceptance statement. The core has no authoritative ownership state. External
decisions may be attached as evidence; only out-of-protocol adapters may
interpret them under adopter policy.

## Event and receipt

The immutable client event is separate from the relay receipt. Relay metadata
MUST NOT be inserted into or rewrite accepted event bytes. The JCS canonical
bytes are the sole normative accepted representation. Raw transport bytes are
discarded by default; optional ingress telemetry is nonnormative and MUST NOT
participate in transcripts, digests, replay, or idempotency.

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

The closed receipt contract is:

```json
{
  "specversion": "0.1",
  "receipt_version": "0.1",
  "receipt_id": "01989f0e-56b7-7e01-915e-a7748f7f6282",
  "event_id": "01989f0e-56b7-7e01-915e-a7748f7f6280",
  "tenant_id": "tenant:example",
  "channel_id": "channel:project-release",
  "channel_uri": "https://coord.example/channels/project-release",
  "principal_id": "principal:alice",
  "participant_id": "session:wave-2",
  "participant_instance_id": "01989f0e-56b7-7e01-915e-a7748f7f6281",
  "session_epoch": 1,
  "cursor": "opaque-relay-cursor",
  "transcript_epoch": 0,
  "sequence": 42,
  "accepted_at": "2026-08-02T16:00:00.123Z",
  "event_digest": "sha-256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "channel_metadata_digest": "sha-256:1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "acl_policy_version": "acl-v3",
  "acl_policy_digest": "sha-256:2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "acl_decision_receipt_id": "decision-7af2",
  "append_outcome": "appended",
  "key_id": "relay-key-2026-08",
  "signature_algorithm": "ed25519",
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

Every receipt field except the advisory copied `participant_id` is relay-derived
or relay-bound; clients MUST NOT choose receipt values through the event body.

The relay authenticates the principal, establishes an authorized tenant, and
issues `participant_instance_id` plus `session_epoch` before publication so a
reused participant label cannot impersonate an earlier process. Receipt
`participant_id` MUST equal `event.participant.id`; the receipt binds it to the
issued instance/epoch. `source` remains asserted, advisory, and non-authorizing.
One tenant maps the exact canonical event channel URI to one immutable
`channel_id`; rebinding is forbidden and migration creates a new mapping.

Receipts are at most 16,384 UTF-8 bytes and contain `key_id`,
`signature_algorithm: "ed25519"`, and a base64url-no-padding signature. The
receipt also binds `channel_metadata_digest`, `acl_policy_version`, its policy
digest and decision receipt, and the admitted high-water `sequence`. Receipt
`acl_policy_version` MUST equal channel metadata `acl_policy_version`. Sequence
starts at 1 and is contiguous within `(tenant_id, channel_id,
transcript_epoch)`. The signature covers JCS of the exact closed receipt schema
with `signature` omitted, domain-separated
by `yukh-coordination-receipt-v0.1` followed by a NUL byte. The signing key MUST
remain outside the event database and its recovery domain. The complete
signature preimage and append record MUST be persisted atomically and be
byte-identical to the later emitted receipt preimage. A receipt authenticates
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

Presence is advisory and ephemeral. A `presence` requires exact timestamps
`observed_at` and `valid_until`; semantic validation requires
`valid_until > observed_at`. Durable presence events are historical observations
and projection MUST NOT treat one as current after `valid_until`. Presence MUST
NOT change a claim, ACL, or authority decision.

### Claim assertions

A claim payload contains a stable `claim_id`, decimal-string generation,
bounded `scope`, bounded `boundary`, optional immutable `governance_ref`, and an
`expected_active_claims`, sorted ascending by lowercase UUID lexical Unicode
code-point order. That set is an advisory observation,
never a precondition. Subject only to the frozen neutral resource limit below,
every schema-valid, authenticated, channel-authorized claim assertion MUST
append. A mismatch emits conflict diagnostics but MUST NOT
reject, serialize, upgrade, or select a claim.

One exact work URI admits at most 32 simultaneously active claim assertions as
a neutral resource bound. A 33rd otherwise valid assertion is rejected before
append with public `RESOURCE_LIMIT`; restricted audit records internal reason
`ACTIVE_CLAIM_LIMIT`. This limit never selects, ranks, releases, or upgrades an
owner.

Concurrent active claims over the same exact work identity MUST project
`conflicting` with every contender. Arrival order, event time, UUID order,
presence, relay sequence, receipts, and external evidence MUST NOT select or
upgrade a winner in the core protocol.

Projection states are exactly `unclaimed`, `claimed`, `conflicting`,
`handoff_offered`, and `released`. `claimed` means one observable active
assertion, not accepted authority.

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

Acceptance MUST reference the exact offer and match its authenticated recipient.
An acceptance after the source claim is released, superseded, changed, or after
another acceptance fails transactional CAS with
`HANDOFF_PRECONDITION_FAILED` and is not appended. Handoff remains an attributed
coordination statement; neither a protocol nor external-evidence field upgrades
it into authoritative ownership.

## Evidence

Evidence contains `uri`, `media_type`, and a mandatory SHA-256 digest over exact
representation bytes. `revision` is optional advisory provider location
metadata and never substitutes for the digest. `declared_size` is a mandatory
bounded decimal string representing the expected byte count. v0.1 supports
SHA-256 only.

A digest proves content identity, not truth, freshness, provenance, CI status, reviewer independence, or authorization. The core relay MUST NOT fetch arbitrary evidence URIs. Verification is performed by a separately authorized client/verifier and reported as new evidence.

`evidence_verification` binds the original descriptor through
`descriptor_digest`, `uri`, `algorithm: sha-256`, and `expected_digest`. Its
outcome is exactly `verified`, `mismatch`, `unavailable`, `unauthorized`, or
`inconclusive`. `verified`/`mismatch` require `observed_digest` and forbid
`reason`; the other outcomes require `reason` and forbid `observed_digest`.
`verifier_policy_version` is required. Any `verifier` label is advisory; the
authenticated verifier is the receipt principal/participant instance. The
signal never rewrites the descriptor or grants authority.

The relay resolves `referenced_event_id`, selects the one descriptor whose
frozen-domain recomputation equals `descriptor_digest`, and requires payload
`uri == descriptor.uri`, `algorithm == descriptor.digest.algorithm`, and
`expected_digest == "sha-256:" + descriptor.digest.value`. Missing, ambiguous,
or unequal bindings are rejected before append as `INVALID_REFERENCE` or
`INVALID_PAYLOAD`; they never become verification observations.

Each formula below outputs the string `sha-256:<lowercase hex of the 32-byte
SHA-256 result>`. Inputs are exactly:
exact domain-separated inputs:

- `descriptor_digest = SHA256(UTF8("yukh.evidence-descriptor.v0.1\0") || JCS(descriptor))`;
- `evidence_set_digest = SHA256(UTF8("yukh.evidence-set.v0.1\0") || JCS(ordered array of complete descriptors))`;
- `boundary_digest = SHA256(UTF8("yukh.handoff-boundary.v0.1\0") || JCS({work_uri,claim_id,claim_generation,boundary,next_action,unresolved_risks}))`.

The array order and object member names above are normative; sets MUST NOT be
sorted or reduced implicitly.

Credentials, secret query parameters, private prompts, inline evidence bodies, and unrestricted logs are forbidden.

## Correlation and family references

For each root `claim`, `question`, or `review_request`, `correlation_id` MUST
equal that root event's `id`. Child events inherit that exact correlation ID.
`answer.question_event_id`, `verdict.review_event_id`, claim lifecycle parent
fields, handoff offer parent claim event, handoff acceptance offer event, and
evidence verification referenced event MUST identify the exact accepted parent;
`causation_id` MUST equal the immediate parent field. A successor claim starts a
new claim correlation (`correlation_id == id`) while causally referencing its
accepted handoff through `predecessor_handoff_event`.

## Ordering, delivery, and replay

- Event time and UUID order are never authoritative ordering.
- Causation defines a partial order.
- The MVP relay assigns a contiguous sequence beginning at 1 per tenant/channel/transcript epoch.
- No global or cross-relay order is promised.
- A missing causal predecessor is rejected with `UNRESOLVED_CAUSATION`; it is never appended, deferred, or silently projected.
- Replay from origin and replay across arbitrary page boundaries MUST produce the same derived state and diagnostics.
- Pagination cursors are tenant/channel-scoped and opaque or integrity-protected.

The closed work projection state is exactly `unclaimed`, `claimed`,
`conflicting`, `handoff_offered`, or `released`, with this precedence for one
exact work URI:

1. more than one active claim yields `conflicting`; handoff never overrides it;
2. exactly one active claim with one or more current valid handoff offers yields `handoff_offered`;
3. exactly one active claim otherwise yields `claimed`;
4. zero active claims with any historical claim yields `released`;
5. no historical claim yields `unclaimed`.

Contender claim IDs and `handoff_offer_ids` are independently sorted ascending
by lowercase UUID lexical Unicode code-point order. Because conflict precedence
ignores handoffs, `handoff_offer_ids` is empty in `conflicting`; it represents
offers only for the single active claim. At most 32 current offers
are admitted per claim; a 33rd is rejected before append with public
`RESOURCE_LIMIT` and restricted internal reason `ACTIVE_HANDOFF_OFFER_LIMIT`.
This is a neutral resource bound, not offer or ownership selection.

A conflict produces exactly one aggregate `CLAIM_CONFLICT` diagnostic containing
every contender claim ID and its corresponding claim event ID, each array
independently sorted ascending. `primary_id` is the lexically smallest lowercase
contender event UUID. Its diagnostic `sequence` is the sequence of the event
that first changes the active set from one to two claims and remains unchanged
while that conflict stays current. If the conflict resolves, any later new
conflict derives a new trigger and sequence.

For `HANDOFF_ACCEPTED_UNCLAIMED`, `primary_id` equals the acceptance event ID and
`sequence` equals that event's channel sequence. For `INCOMPLETE_TRANSCRIPT` and
`NON_ACTIVE_TRANSCRIPT`, `primary_id` is the canonical `transcript_id` and
`sequence` equals `diagnostics_high_water_sequence`.

`transcript_id` is a derived non-event identifier, so its UUIDv5 form does not
relax the UUIDv7-only event-ID rule. It is UUIDv5 using fixed namespace
`44a2ca56-05fd-5e2c-aba3-ef07363b75ae` and the canonical UTF-8 name bytes:
`tenant_id || U+0000 || channel_uri || U+0000 || canonical unsigned decimal
transcript_epoch`. Inputs are the exact receipt/channel strings with no Unicode
or URI normalization. Output is lowercase canonical hyphenated UUID.

Diagnostics contain no free detail and are stably ordered by channel
sequence ascending, code ascending, then `primary_id` ascending, all by Unicode
code-point order. For non-conflict diagnostics `primary_id` is the required
event ID, claim ID, or transcript identifier defined by its schema case.
Implementations MUST emit byte-equivalent projections and diagnostic order for
the same complete transcript.

`projection.diagnostics` contains only current derived work-projection
diagnostics. `diagnostics_high_water_sequence` MUST equal `as_of_sequence`; this
cross-field equality is enforced by semantic conformance validation because
JSON Schema 2020-12 cannot compare sibling values. It is not historical rejection,
security, audit, or presence history. There is at most one aggregate entry per
closed diagnostic code. Superseded or resolved entries disappear
deterministically. Rejected events and presence events never create work
projection diagnostics; restricted audit owns rejection history. The invariant
`maxItems: 32` is a compatibility bound for the closed code set, never a
truncation policy.

## Idempotency and collisions

`(tenant, immutable channel mapping, event.id)` is unique. Resubmission of
identical JCS canonical bytes always returns the byte-identical original signed
receipt, whose `append_outcome` remains `appended`, without a second append or a
new protocol receipt. Duplicate observation may be recorded only in restricted
security audit. The same ID with different canonical bytes is rejected and
security-audited as `ID_COLLISION`. Similar payloads with distinct IDs remain
distinct events.

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

Stored events retain only the accepted JCS canonical bytes and version as the
normative event representation. Raw ingress is discarded; optional nonnormative
ingress telemetry is never transcript, replay, digest, or idempotency input.
Migrations create derived projections and never rewrite canonical history.
Reverse-DNS extension keys may be preserved but MUST NOT change core semantics.

Removing fields, changing requiredness, canonicalization, projection semantics, rejection behavior, or authority meaning requires a major version.

## Error contract

Errors use `application/problem+json` and a stable code. The initial codes include:

`INVALID_ENVELOPE`, `UNSUPPORTED_VERSION`, `INVALID_EVENT_TYPE`, `INVALID_PAYLOAD`, `INVALID_REFERENCE`, `CROSS_CHANNEL_REFERENCE`, `UNRESOLVED_CAUSATION`, `CAUSAL_CYCLE`, `ID_COLLISION`, `INVALID_CLAIM_TRANSITION`, `INVALID_HANDOFF_PARTICIPANT`, `HANDOFF_PRECONDITION_FAILED`, `ALREADY_ACCEPTED_HANDOFF`, `EVIDENCE_INTEGRITY_REQUIRED`, `RESOURCE_LIMIT`, `ACCESS_DENIED`, and `TEMPORARILY_UNAVAILABLE`. `CLAIM_CONFLICT` is a projection diagnostic, never a claim-append rejection Problem.

Rejected events are not protocol events. Security-relevant rejection metadata belongs to a separate restricted audit log.

Problem documents are at most 16,384 UTF-8 bytes. Unauthorized callers receive
the exact non-enumerating shape fixed by `problem-0.1.schema.json`: type
`https://yukh.dev/problems/access-denied`, title `Access denied`, status `403`,
code `ACCESS_DENIED`, and `retryable: false`. It forbids detail, event, and
internal fields. Processing precedence is authenticate, establish tenant, then
authorize. No later validation or lookup result is disclosed before successful
authorization. A bounded opaque `trace_id` supports restricted audit correlation.

## Immutable channel metadata

Before the first event, the relay persists closed channel metadata binding the
tenant ID, exact channel URI, immutable internal channel ID, ACL policy version
and digest,
retention policy digest and epoch, and creation time. There is no default
retention. Metadata updates create a new policy/retention epoch and digest;
identity fields never change. Every signed receipt binds the applicable metadata
digest and policy version together with the admitted high-water sequence.
`channel_metadata_digest` is lowercase SHA-256 over
`UTF8("yukh.channel-metadata.v0.1\0") || JCS(channel_metadata)`.

## Transcript completeness and retention

A transcript has two independent dimensions: completeness is exactly `complete`
or `incomplete`; lifecycle is exactly `active`, `redacted`, or `deleted`. A
transcript is `complete` only when replay starts at the log origin, ends at a
signed relay high-water receipt, has a contiguous verified sequence, validates
all receipt signatures and event digests, and resolves all references. Any
omission, unverifiable receipt, mismatch, missing predecessor, or unknown
version makes it `incomplete`. Incomplete or non-`active` transcripts may be
inspected but MUST NOT assert final claim, handoff, review, or presence
projections.

There is no default retention period. A relay MUST refuse channel creation
until an accountable retention policy is supplied and bound into channel
metadata. Redaction sets lifecycle `redacted`; deletion sets it `deleted`; both
also make affected transcripts `incomplete`. Neither silently rewrites accepted
canonical bytes nor preserves a false completeness claim.

## Required conformance evidence

Acceptance requires schemas, exact canonical byte vectors, SHA-256 manifests, positive/negative fixtures for every signal, and deterministic projection fixtures.

The adversarial transcript MUST cover spoofed participant data, concurrent claims, exact duplicates, same-ID/different-byte collision, reordered client time, expired presence, late and multiple handoff acceptance, changed/unavailable evidence, wrong evidence digest, arbitrary page boundaries, and denied cross-tenant access without existence leakage.

Two independent implementations from different runtime families MUST produce byte-identical canonical bytes, derived state, and diagnostics.

## Handoff CAS and successor claim

`handoff_accept` is the only core transactional compare-and-set. It covers the exact offer event, source claim
generation, authenticated intended `participant_instance_id`, and unchanged
active source claim. Changed or released state is rejected. Acceptance closes
the offer but neither transfers nor creates ownership. The recipient publishes
a separate `claim` with a new claim ID/generation and
`predecessor_handoff_event`; ordinary claim append semantics apply. Until then,
the exact five-state work projection remains determined by the source claim
lifecycle and emits `HANDOFF_ACCEPTED_UNCLAIMED` as a diagnostic; it does not
invent a sixth state.

## Remaining qualification evidence

Issue #4 must prove all closed schemas, limits, nesting/number rejection,
canonical bytes, signed receipts, claim conflict/release generations, handoff
CAS, evidence verification, transcript completeness, retention binding,
non-enumerating errors, and cross-runtime equivalence. These are evidence gates,
not remaining implementation discretion.

Federation, portable cursors, automatic leases, winner election, retention
policy selection, redaction mechanisms, and reviewer-independence inference are
excluded from v0.1.
