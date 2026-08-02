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

Issue #4 owns positive/negative fixtures and independent qualification evidence.
