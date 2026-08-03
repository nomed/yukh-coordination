# Relay application services

This package owns transport-neutral use cases between an admitted request and
the persistence/signing ports. HTTP handlers, Matrix bridges and other clients
must call these services rather than assembling relay transactions directly.

## Signed append

For a new event the service:

1. checks idempotency before selecting a key;
2. selects an eligible key before the append transaction;
3. requires the prepared record to preserve that key ID and algorithm;
4. commits the event and complete unsigned receipt preimage;
5. signs outside the event-store failure domain;
6. attaches the exact signature idempotently;
7. returns success only after the signed record is durable.

If signing or signature attachment fails, the event remains committed and the
service returns `relay.ErrSignaturePending` with no success result. An exact
retry finds the original record, selects no replacement key, signs its persisted
preimage and returns the original receipt identity. A retry of an already signed
record performs neither key selection nor signing.

Authentication, authorization and HTTP error mapping remain edge boundaries;
the admitted context now carries their server-derived bindings explicitly.

## Relay application

`RelayApplication` implements RFC-0005 without owning a transport or provider.
It validates exact canonical event bytes against the public embedded schema,
checks immutable channel and ACL bindings, prepares canonical signed receipts,
builds deterministic bounded pages and performs subscribe-before-read live
delivery. Live notifications are bounded wake-ups only; every emitted record is
read again from the durable store.

The stateful validator reconstructs the admitted transcript inside the same
adapter transaction that allocates the next sequence. It resolves causation and
typed references, enforces claim and offer limits, verifies evidence bindings,
and applies handoff acceptance as a recipient-bound compare-and-set. No
read-before-append race can admit two transitions against the same stale view.
