# Session 2026-08-05 — Backup and completion evidence contract

## Authority and scope

- Governing issue: #156
- Accepted design: RFC-0023
- Predecessor: merged verified primary-removal candidate #155 at `af129d6`
- Scope: authority-neutral contract foundation only

## Candidate delivered

- canonical obligation, signed custodian-receipt and explicit completion
  evidence schemas with exact domain-separated digests;
- exactly three ordered custody domains and deadlines copied from immutable
  intent evidence;
- public-verification-only receipt capability with no signer or private key;
- incompatible port correction from `Complete(OperationReference)` to
  `Complete(CompletionEvidence)`;
- exact retry, cross-binding and clone helpers;
- deterministic bounded recovery classification.

Review correction records recovery as ordered per-domain findings so mixed
failure/deadline incidents retain both causes. A public verifier returning the
closed unavailable sentinel produces recoverable `verification_unavailable`
instead of permanent contract corruption.

## Incident rule frozen

A failure receipt never satisfies an obligation. A success after the immutable
deadline is durable but non-qualifying. A later distinct success after an
earlier failure remains append-only contradictory evidence and cannot resolve
the incident or authorize completion. Resolution requires a future accepted
incident-resolution contract; no overwrite or ambient completion gate exists.

## Qualification evidence

Go schema and lifecycle tests cover ordered obligations, cross-binding,
signature verification, exact retry, missing evidence, failure, deadline miss,
duplicate/replacement, later success after failure and explicit audit-bound
completion. Independent Python and JavaScript canonicalizers agree on the
obligation, custodian receipt and completion bytes and domain-separated
digests. The full Go suite, Node suite and repository-structure gate pass.

## Intentionally incomplete

No SQLite schema or adapter, provider call, backup deletion, audit-ledger write,
worker/scheduler, restore execution, physical media sanitization, HTTP/SSE or
client change, executable, real data, deployment, JetStream lifecycle, Matrix,
MCP or production use is implemented or authorized.

## Next boundary

After review and merge of #156, a separately approved SQLite issue may
materialize obligations, record synthetic verified receipts, recover pending
state and complete operations against this exact contract. It may not perform
provider deletion or operate on real data.
