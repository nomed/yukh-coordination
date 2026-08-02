# Protocol schema boundary

These closed JSON Schemas are machine-readable parts of RFC-0001 Draft 0.1.
They do not make the RFC accepted.

JSON Schema validates structure and character counts. A conforming decoder also
MUST enforce the RFC's UTF-8 byte limits (64 KiB event, 16 KiB receipt/problem,
2,048 bytes per URI), maximum nesting depth 16, duplicate-key rejection,
well-formed UTF-8/no BOM/no unpaired surrogates, JCS canonicalization, semantic
reference rules, root `correlation_id == id`, child correlation inheritance,
parent-field/`causation_id` equality, handoff-only transactional CAS, and the
absence of JSON numbers anywhere in client events. Receipts and Problem Details
deliberately permit only their explicitly bounded safe-integer fields. Claim
assertions never use CAS and always append after schema/auth/channel checks.
Semantic validation also enforces `presence.valid_until > observed_at`, sorted
claim contenders/diagnostics, contiguous receipt sequence from 1, equality of
receipt and channel-metadata ACL versions/digests, receipt participant binding,
and conditional evidence-verification fields. Only JCS canonical accepted bytes
are normative; raw ingress is discarded or nonnormative telemetry.
Evidence-verification equality and descriptor-domain recomputation are semantic
checks. Projection precedence and aggregate diagnostic ordering are normative;
the 32-active-claim bound is a neutral pre-append resource check.
Projection `handoff_offer_ids` and diagnostics are sorted derived current state;
diagnostic codes are unique aggregates and resolved entries disappear. Rejected
events and presence history belong outside the work projection. The 32-offer
per-claim bound is another neutral pre-append resource check.
Semantic validation requires `diagnostics_high_water_sequence ==
as_of_sequence`, each per-code `primary_id`/`sequence` derivation, independently
sorted contender claim/event arrays, and the fixed-namespace UUIDv5 transcript
identifier. UUIDv5 is derived metadata, never an event ID.

`test-vectors/diagnostic-derivation-0.1.json` freezes the initial byte-exact
UUIDv5, high-water, conflict-trigger, and handoff-acceptance derivation vectors.

Issue #4 owns positive/negative fixtures and independent qualification evidence.
