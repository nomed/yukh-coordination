# Session 2026-08-03 — private staging TLS listener

## Authority and scope

- Governing issue: #90
- Bounded increment: #99
- Accepted design: RFC-0022
- Foundation dependency: #95 delivered by PR #96 at `148dea7`

## Delivered candidate

- exact-address public listener terminating TLS 1.3 directly;
- explicit trust-bundle and exact public-identity certificate verification;
- reuse of the qualified RFC-0015 HTTP handler and two-phase authorization
  pipeline without copying routes or schemas;
- conjunctive, fail-closed readiness probes that deny public admission before
  authentication or replay reservation;
- loopback operations surface limited to liveness, readiness and one
  low-cardinality readiness gauge;
- bounded headers, reads, writes, idle time and shutdown;
- hermetic generated-root end-to-end request and negative TLS/authority tests.

## Verification

- `go test -race ./internal/primitivesstaging`
- `go test ./...`
- `go vet ./internal/primitivesstaging`
- `git diff --check`

## Intentionally incomplete

Concrete mandatory audit, capability-key custody and JetStream KV/epoch
composition remain separate focused increments. No infrastructure, real
credential, externally exposed listener, MCP request, provider execution,
protected mutation or production deployment is included or authorized.

## Next boundary

After #99 is reviewed and merged, separately compose the RFC-0011-compatible
audit gate before the capability and JetStream dependencies. A live MCP
connection remains unauthorized until the complete hermetic service profile is
qualified and the later provisioning and live-window approvals are recorded.
