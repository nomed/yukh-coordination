# SESSION-2026-08-03-10: JetStream adapter bootstrap

- Governing issue: #5
- Pull request: #25
- Status: Active

## Objective

Establish the accepted RFC-0006 adapter boundary against a real JetStream
server before implementing its command reducer.

## Implemented

- pinned NATS Go client;
- deterministic hashed tenant subjects with no raw identity leakage;
- explicit bootstrap versus fail-closed open behavior;
- exact file-backed, discard-new, no-delete/no-purge/no-rollup/no-atomic-batch
  stream profile;
- rejection of mismatched existing stream configuration;
- real disposable `nats-server` 2.12 qualification in CI.

## Boundary retained

The package deliberately does not claim `relay.Store` yet. Command codec,
reducer, compare-and-publish mutation and live consumer behavior remain the next
increment. No endpoint, credential or deployment default is introduced.

## Next

Publish this bootstrap foundation, then implement the canonical command reducer
and optimistic Store operations against the qualified stream.
