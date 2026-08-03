# Protocol admission

This package is the Go admission implementation for the accepted v0.1 protocol.
It compiles the authoritative files from the top-level `schema/` package; no
private schema copy exists under `internal/`.

Admission rejects invalid UTF-8, oversized input, duplicate object members,
numbers, excessive nesting, non-JCS bytes, schema violations and the frozen
event-local semantic violations. The fixture test qualifies every published
positive and negative event fixture against the independent Python and
JavaScript corpus.

Stateful reference resolution, resource limits and transactional handoff CAS
depend on durable transcript state and therefore belong to the application
transition validator, not this byte-level package.
