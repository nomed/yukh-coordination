# SESSION-2026-08-03-01: Reference relay foundation

- Governing issue: #5
- Pull request: #16
- Status: Active

## Objective

Start the reference relay without leaking SQLite, JetStream or Matrix into the
public protocol, and establish deterministic repository memory before further
implementation.

## Work completed

- accepted the Go, HTTP/SSE, SQLite, JetStream and Matrix delivery boundary;
- defined the neutral append/replay persistence port;
- qualified the port with a concurrent in-memory adapter;
- consolidated durable repository context under `.context`.

## Evidence and validation

- Go unit tests and vet pass;
- existing JavaScript replay tests pass;
- cross-runtime canonical projection qualification passes;
- GitHub Actions race test passes.

## Decisions discovered

- RFC-0003 defines the runtime boundary and delivery order;
- ADR-0002 makes `.context` canonical and closes the top-level directory map.

## Context impact

The previous `docs/adr`, `docs/rfc` and `docs/security` trees are canonicalized
under `.context`. No duplicate compatibility copies are retained.

## Risks and unresolved work

SQLite durability, signed acknowledgement recovery, HTTP/SSE backpressure,
JetStream topology and Matrix mapping remain unqualified.
