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

Authentication, authorization, protocol validation and HTTP error mapping are
separate preceding/following boundaries; this package does not infer them.
