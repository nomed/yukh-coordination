# Session 2026-08-03 — private staging mandatory audit gate

## Authority and scope

- Governing issue: #90
- Bounded increment: #102
- Accepted designs: RFC-0011 and RFC-0022
- Runtime dependency: #99 delivered by PR #100 at `9884171`

## Delivered candidate

- reuse of the accepted RFC-0011 SQLite chain, receipts, Merkle verification
  and restart behavior;
- closed staging record vocabulary for authentication, authorization and
  lifecycle decisions without changing existing record meanings;
- append-before-result wrappers for authentication and action/scope
  authorization;
- runtime audit for registration load, TLS readiness, startup, unready public
  admission and shutdown;
- closed credential-expiry denial and readiness latched false after append
  uncertainty until a verified restart;
- audit structural verification as a conjunctive readiness gate;
- domain-separated derived identity references and prohibited-data tests;
- explicit audit database path in the closed non-secret configuration.

## Verification

- `go test -race ./internal/primitivesstaging ./internal/relay/audit ./internal/relay/audit/sqlite`
- `go test ./...`
- `go vet ./...`
- `git diff --check`

## Intentionally incomplete

Capability-key custody, exact JetStream KV/epoch composition, operated
checkpoint signer/witness readiness, infrastructure, live credentials,
listener exposure, MCP requests, provider execution, protected mutation and
production deployment remain excluded.

## Next boundary

After #102 is reviewed and merged, compose descriptor-delivered capability-key
custody as a separate increment. Live MCP traffic remains unauthorized until
the complete hermetic profile, deployment evidence and two later human gates
are satisfied.
