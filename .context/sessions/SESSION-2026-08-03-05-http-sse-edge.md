# SESSION-2026-08-03-05: HTTP/SSE edge

- Governing issue: #5
- Pull request: pending
- Status: Active

## Objective

Implement the accepted RFC-0004 transport boundary without embedding an
identity provider, policy engine, signer or storage adapter in the handler.

## Work completed

- implemented strict routes, canonical decimal cursors and media types;
- enforced TLS and bounded Bearer extraction;
- introduced provider-neutral authenticator, authorizer and application ports;
- enforced tenant derivation from authenticated identity;
- implemented non-enumerating denial and bounded Problem Details;
- implemented append outcome mapping with no unsigned success;
- implemented SSE ordering, reconnect ID, unsigned boundary, heartbeat,
  revocation signal, write deadline and maximum lifetime.

## Evidence and validation

Handler tests cover boundary ordering, tenant spoofing headers, denial,
canonical routes/cursors, append outcomes, signature pending, SSE ordering,
unsigned cursor behavior, revocation and TLS enforcement.

## Decisions discovered

The public transcript epoch and sequence cursor are canonical decimal JSON-safe
integers bounded to `9007199254740991`, matching the protocol schemas.

## Context impact

No new decision record is required. This increment implements accepted
RFC-0004. Provider implementations remain outside the edge.

## Risks and unresolved work

The application port still requires the Go canonical event validator, receipt
serializer, bounded replay page builder and race-free store-to-stream adapter.
No server executable or deployment is authorized.
