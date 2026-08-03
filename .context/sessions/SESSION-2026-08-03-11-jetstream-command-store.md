# Session: JetStream command Store

- Date: 2026-08-03
- Governing issue: #5
- Governing RFC: RFC-0006
- Branch: `agent/jetstream-command-store`

## Outcome

Implemented the RFC-0006 durable Store boundary on the adapter-owned JetStream
command log. The adapter now encodes closed canonical commands, rebuilds tenant
state through deterministic replay and serializes mutations with
`Nats-Expected-Last-Subject-Sequence`.

The reducer fails closed on non-canonical, unknown, cross-tenant or
invariant-breaking history. KV, `Nats-Msg-Id`, snapshots and atomic batch
publication remain absent by design.

## Evidence

- `relay.Store` compile-time conformance;
- real `nats-server` tests for concurrent gap-free appends, exact retry,
  event collision, separate signature attachment and full reopen/replay;
- simulated lost acknowledgements after successful append and signature
  publication, reconciled from immutable log identity;
- hostile tenant/payload subject mismatch rejected during replay;
- complete Go test suite and `go vet` pass locally.

The local image lacked a C compiler, so the race-enabled suite is delegated to
the existing GitHub Actions environment before merge.

## Boundary

This increment does not implement live notification or connect the runtime to
Matrix. The next focused increment is the bounded ephemeral JetStream consumer
defined by RFC-0006; notifications remain wake-up hints and durable reads stay
authoritative.
