# Protocol schema boundary

These closed JSON Schemas are machine-readable parts of RFC-0001 Draft 0.1.
They do not make the RFC accepted.

JSON Schema validates structure and character counts. A conforming decoder also
MUST enforce the RFC's UTF-8 byte limits (64 KiB event, 16 KiB receipt/problem,
2,048 bytes per URI), maximum nesting depth 16, duplicate-key rejection,
well-formed UTF-8/no BOM/no unpaired surrogates, JCS canonicalization, semantic
reference and CAS rules, and the absence of JSON numbers anywhere in client
events. Receipts and Problem Details deliberately permit only their explicitly
bounded safe-integer fields.

Issue #4 owns positive/negative fixtures and independent qualification evidence.
