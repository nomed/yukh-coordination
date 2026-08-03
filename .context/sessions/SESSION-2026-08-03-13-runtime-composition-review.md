# Session: Runtime composition contract review

- Date: 2026-08-03
- Governing issue: #5
- Proposed decision: RFC-0007
- Branch: `agent/relay-runtime-composition-rfc`

## Outcome

Proposed the composition and lifecycle boundary required before assembling the
qualified relay packages. The review found that an honest standalone binary is
not yet possible: no accepted profile supplies session identity, ACL decisions,
channel provisioning or signing-key custody.

RFC-0007 therefore proposes an internal, typed composition root that owns HTTP
serving, graceful shutdown and explicit resource cleanup while receiving every
policy and adapter dependency from its caller. It explicitly forbids permissive
development providers and keeps `cmd/` unauthorized until a provider profile is
accepted.

## Boundary

This session changes documentation only. It does not add runtime code, a new
top-level directory, provider behavior, configuration, routes, credentials or
deployment claims. Owner acceptance is required before implementation.
