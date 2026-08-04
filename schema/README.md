# Protocol schema boundary

`coordination-primitives-1.schema.json` publishes the closed request, response
and Problem Details shapes for the separate RFC-0015 primitives service. It
does not add a relay route or expose provider storage fields.

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

The four `transcript-lifecycle-*-0.1.schema.json` contracts publish the closed
RFC-0023 policy, operation intent, append-only marker and unsigned receipt
preimage shapes. They expose no destructive route or adapter. Semantic
validation additionally requires exact policy-digest recomputation, UTC
millisecond ordering, sorted unique selective-redaction sequences, the exact
three-domain backup deadline order, allowed monotonic lifecycle transitions and
UUIDv7 operation/receipt identities. The canonical byte and digest fixtures are
frozen in `test-vectors/transcript-lifecycle-0.1.json`.

Issue #4 owns the core v0.1 protocol fixtures and their independent
qualification evidence. Issue #135 owns the bounded RFC-0023 lifecycle vectors;
later adapter and destructive-saga qualification remains separately gated.
