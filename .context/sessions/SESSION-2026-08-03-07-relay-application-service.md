# SESSION-2026-08-03-07: Relay application service

- Governing issue: #5
- Pull request: pending
- Status: Active

## Objective

Implement the accepted RFC-0005 application boundary without introducing an
identity provider, broker adapter, executable or deployment.

## Implemented

- Go event admission using the authoritative embedded schema tree, strict JSON
  parsing, JCS equality and event-local semantic validation;
- immutable canonical channel metadata and lifecycle lookup in memory and
  SQLite stores, including fail-closed schema-v3 migration;
- structured admitted ACL bindings at the HTTP/application boundary;
- server-derived canonical receipt preimage and signed-receipt serialization;
- canonical record and bounded transcript-page serialization;
- subscribe-before-read streaming with bounded coalesced notifications and
  durable reads as the sole record source;
- exact-retry, wrong-channel, fixture-equivalence and replay/live tests.

## Boundary retained

Stateful RFC-0001 admission rules—causal/reference resolution, claim resource
limits and handoff transactional CAS—are not inferred by the byte validator.
They remain the next application increment and block an executable relay.

## Next

Publish this independently qualified application foundation, then implement the
stateful transition validator against the same Store boundary.
