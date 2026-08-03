# Session 2026-08-03 — private staging capability-key custody

## Authority and scope

- Governing issue: #90
- Bounded increment: #104
- Accepted designs: RFC-0019 and RFC-0022
- Audit dependency: #102 delivered by PR #103 at `b18942e`

## Delivered candidate

- one-shot, bounded descriptor consumption and immediate descriptor close;
- canonical closed keyring with one active key and at most one decrypt-only
  predecessor;
- exact maximum-lease retention, non-overlapping seal windows and unique IDs;
- existing neutral primitives sealing-key provider contract;
- best-effort Linux memory locking and deterministic clear/unlock at shutdown;
- mandatory audit for key load and zeroization;
- runtime-required custody readiness and close-before-stopped ordering;
- rotation, stale-capability, malformed/truncated/oversized input, expiry,
  reuse, audit-failure, redaction and backing-buffer zeroization tests.

## Verification

- `go test -race ./internal/primitivesstaging ./internal/primitives ./internal/relay/audit`
- `go test ./...`
- `go vet ./...`
- `git diff --check`

## Intentionally incomplete

Exact JetStream KV/bucket/epoch composition, NATS descriptor custody,
infrastructure, live credentials, listener exposure, MCP requests, provider
execution, protected mutation and production deployment remain excluded.

## Next boundary

After #104 is reviewed and merged, compose the exact RFC-0012 JetStream stores,
capability budget and restore epoch as a separate increment. Live MCP traffic
remains unauthorized until complete hermetic qualification and the later
provisioning plus live-window approvals.
