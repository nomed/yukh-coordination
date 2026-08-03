# RFC-0017: Two-phase authorization for sealed capabilities

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #65
- Governing architecture: ADR-0001, RFC-0015 and RFC-0016

The project owner explicitly accepted this RFC on 2026-08-03. Acceptance
authorizes the separately reviewed authorization-port and synthetic HTTP
implementation described here. It does not authorize deployment, credentials,
publication, protected consumer use or live apply.

## Decision requested

Clarify the RFC-0015 authorization order for lease operations whose logical
scope exists only inside an authenticated-encrypted capability.

Acceptance authorizes the separate authorization-port and synthetic HTTP
implementation described here. It does not authorize deployment, credentials,
publication, protected consumer use or live apply.

## Contradiction

RFC-0015 requires authorization before capability lookup and requires the
authorizer to decide an exact action for a logical scope. `inspect`, `renew` and
`release` accept exactly one sealed capability; they do not carry a public scope
digest. Therefore scoped authorization cannot occur before authenticated
opening without exposing or duplicating the scope outside the capability.

## Required order

The HTTP application uses two mandatory, deny-by-default ports:

~~~text
frame -> authenticate -> authorize action -> AEAD open
      -> authorize recovered scope -> Resume/store operation
~~~

`PrimitiveActionAuthorizer` decides exactly one closed action for the admitted
tenant/principal. It runs once before any capability parsing, key-provider call
or existence lookup. Denial uses the common non-enumerating response.

After successful AEAD authentication, `PrimitiveScopeAuthorizer` receives the
same immutable identity, exact action and recovered internal scope digest. It
runs once before `Resume`, `Valid`, `Renew`, `Release` or any JetStream access.
Denial exposes neither capability validity nor scope and produces no store call.

Nonce consume and lease acquire already carry `scope_digest`. They run action
authorization and scoped authorization in that order before deriving a store
key or calling a store. No capability is opened for those operations.

Malformed framing or authentication fails before either authorizer. A malformed,
unknown-key or AEAD-invalid capability fails after action authorization but
before scoped authorization. Provider unavailability remains a sanitized
temporary failure. Neither phase grants authority over the protected operation.

## Bounds and compatibility

Each request invokes authentication once, action authorization once and scoped
authorization at most once. There is no retry, fallback, polling, sleep or
background policy lookup. Both ports receive closed values rather than HTTP
requests, generic maps, credentials or provider bodies.

This clarification changes no route, request/response schema, capability wire
format, bucket, subject, stored value or RFC-0006 behavior. Public callers still
submit only the capability for inspect, renew and release. The recovered scope
never enters logs, diagnostics, audit correlation fields or public output.

## Qualification

Implementation must prove exact call order/count for allow, action deny, invalid
capability, scope deny and store failure; both denial paths are non-enumerating;
invalid capabilities never reach scoped authorization; scope denial never
reaches coordination storage; tenant substitution fails AEAD authentication;
and no sensitive input or provider error appears in output.

## Alternatives rejected

- A plaintext scope in the capability envelope leaks correlation material.
- Repeating scope in the request permits substitution and changes the accepted
  closed schema.
- Opening before any authorization permits unauthorized key-provider work.
- One unscoped authorization silently drops the accepted logical-scope policy.
