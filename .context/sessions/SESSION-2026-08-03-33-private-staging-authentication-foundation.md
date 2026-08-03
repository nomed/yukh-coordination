# Session 2026-08-03 — private staging authentication foundation

## Authority and scope

- Governing implementation issue: #90
- Bounded increment: #95
- Accepted design: RFC-0022
- Dependency: the MCP RFC-0006 consumer contract is stable after MCP PR #51

This increment implements the Coordination-owned security material required
before a listener can exist. It intentionally does not implement or expose a
listener and does not send MCP traffic.

## Delivered candidate

- closed, bounded private-staging configuration with explicit HTTPS authority,
  private/loopback literal binds, distinct inherited descriptors and secure
  path validation;
- canonical Ed25519-signed, short-lived workload registration bound to an exact
  identity, five primitive actions, token digest and P-256 DPoP thumbprint;
- strict ES256 DPoP verification for exact POST target and credential hash;
- durable SQLite replay reservation with atomic single-winner behavior,
  bounded retention state, clock high-water fencing and fail-closed readiness;
- fixed action authorization bound to the signed identity;
- negative, restart and concurrent replay tests.

## Verification

- `go test ./internal/primitivesstaging`
- `go test ./...`

The temporary Go toolchain used for local verification lives outside the
repository. GitHub checks remain the authoritative clean-run evidence after the
draft pull request is published.

## Explicitly incomplete

No listener, executable, TLS runtime, route mapping, operations endpoint,
JetStream composition, capability-key composition, audit-ledger composition,
infrastructure, credentials, live MCP request, provider execution, protected
mutation or production use is included or authorized.

## Next boundary

After #95 is reviewed and merged, Coordination may take a separate bounded
increment for the private TLS listener and primitives pipeline composition,
still using hermetic credentials and without live MCP traffic.
