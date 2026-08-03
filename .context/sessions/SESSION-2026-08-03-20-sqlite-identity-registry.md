# Session: SQLite identity and lifecycle registry

- Date: 2026-08-03
- Governing issue: #5
- Accepted decision: RFC-0010
- Branch: `agent/sqlite-identity-registry`

## Outcome

Implemented the second RFC-0010 delivery increment as an isolated SQLite
identity adapter. The schema is STRICT and separate from the event store. Its
closed operations reserve bootstrap proofs, allocate monotonic epochs, create
pending sessions, activate an exact audited operation, authenticate and reserve
a proof atomically, revoke exact active sessions, materialize expiry and clean
replay rows in bounded batches.

The registry persists wall-clock rollback fences and restore fences. A restored
database cannot admit work until the later recovery composition supplies a
verified database-matched, complete and monotonic set of epoch floors plus its
receipt. Inactive subscriptions register before their durable recheck, while a
single owned scheduler closes expiry signals.

## Boundary

This increment adds no session-token generator, audit implementation,
checkpoint signature verifier, authentication provider composition, public
HTTP route, process configuration or executable. The existing event Store is
unchanged.

## Evidence

- concurrent reuse of one proof commits exactly once;
- pending sessions are abandoned and epochs remain consumed across reopen and
  abrupt subprocess exit;
- activation retry, revocation, expiry signal, clock rollback/recovery and
  restore-floor behavior have deterministic tests;
- schema version and durability pragmas are asserted;
- the complete repository passes the race detector with real JetStream and
  passes `go vet`.
