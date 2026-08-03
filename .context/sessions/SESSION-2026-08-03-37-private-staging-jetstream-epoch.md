# Session 2026-08-03 — private staging JetStream/epoch composition

## Authority and scope

- Governing issue: #90
- Bounded increment: #108
- Accepted designs: RFC-0012, RFC-0019 and RFC-0022
- Custody dependency: #104 delivered by PR #106 at `90b0909`

## Delivered candidate

- closed loopback-only NATS connection, timeout, replica, retention, replay-safety,
  capability-budget and restore-epoch configuration;
- bounded one-shot NATS credential descriptor custody with immediate descriptor
  close, best-effort memory lock and deterministic clear on shutdown;
- bootstrap-disabled composition of the existing nonce, fenced-lease and
  capability-budget JetStream KV stores;
- exact live bucket/epoch probes and fail-closed readiness;
- mandatory redacted storage-epoch audit;
- dependency-close-before-key-zeroization runtime shutdown ordering;
- descriptor reuse/size bounds, mismatch, audit failure, dependency-loss,
  redaction and zeroization tests alongside the existing disposable-JetStream
  suite.

## Verification

- `YUKH_NATS_SERVER=... go test -race ./...`
- `go test ./...`
- `go vet ./...`
- `git diff --check`

## Intentionally incomplete

Bucket bootstrap, infrastructure provisioning, live credentials, listener
exposure, MCP requests, provider execution, protected mutation and production
deployment remain excluded. Relay-adapter epic #14 is not taken in charge.

## Next boundary

After #108 is reviewed and merged, publish the immutable RFC-0022
implementation commit and a redacted deployment plan. Provisioning still
requires explicit owner approval, followed by a separate approval for one live
qualification window.
