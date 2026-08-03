# Session 2026-08-03 — private staging executable assembly

## Authority and scope

- Governing issue: #90
- Bounded increment: #115
- Accepted design: RFC-0022
- Downstream dependency: `nomed/yukh-mcp#50`, still blocked

## Delivered candidate

- one executable under the existing `internal/` repository responsibility;
- exactly one absolute closed configuration path and fixed inherited NATS/key
  descriptor slots;
- complete registration, replay, audit, TLS, key, JetStream, primitives,
  handler, readiness and runtime assembly;
- signal-driven bounded shutdown and fixed non-sensitive failure output;
- hermetic construction/serve/shutdown and negative executable-contract tests;
- reproducible double-build check with embedded Git revision.

## Cross-repository audit

- MCP #50 remains open and now records #115 plus unclaimed bootstrap #117
  successor; no MCP implementation or live request is authorized;
- Projects #54 is intentionally independent and remains open; Projects has no
  RFC-0022 claim or task to integrate or close;
- Coordination relay adapter #14 remains unrelated and unclaimed here.

## Verification

- `.github/scripts/qualify-primitives-executable.sh`
- `go test -race ./internal/primitivesstaging/...`
- `go test ./...`
- `go vet ./...`
- repository structure and `git diff --check`

## Intentionally incomplete

The separately reviewed three-bucket bootstrap operation #117, a new immutable
candidate record and deployment-plan reconciliation remain incomplete.
Infrastructure, credentials, listener exposure, MCP traffic, provider
execution, protected mutation and production use remain excluded.

## Next boundary

After #115 is reviewed and merged, claim only accountable bootstrap #117
increment. Its merge and a reconciled immutable record are prerequisites to any
request for provisioning approval; a later live window still needs a second
explicit approval.
