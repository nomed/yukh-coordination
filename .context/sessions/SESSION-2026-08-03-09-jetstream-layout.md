# SESSION-2026-08-03-09: JetStream adapter layout

- Governing issue: #5
- Pull request: #24
- Status: Complete

## Objective

Resolve the JetStream layout deferred by RFC-0003 without weakening the atomic
Store and stateful-admission contract.

## Findings

- KV CAS plus stream publish cannot form one Yukh acceptance transaction.
- `Nats-Expected-Last-Subject-Sequence` can serialize one tenant log without
  imposing cross-tenant protocol order.
- JetStream message deduplication is ID-only and window-bounded, so it cannot
  implement Yukh byte-exact lifetime idempotency.
- JetStream messages are immutable; signature attachment must be a second
  idempotent log command, matching the signer separation already implemented.
- filtered JetStream consumption is suitable for durable wake-up hints; Core
  NATS alone is not.

## Action

Proposed RFC-0006 with the tenant-log command model, two sequence domains,
optimistic retry/reconciliation rules, strict stream profile and real-server
qualification requirements.

## Next

The owner accepted RFC-0006 on 2026-08-03. Implement the adapter in
`internal/relay/jetstream` without changing the public HTTP/SSE contract.
