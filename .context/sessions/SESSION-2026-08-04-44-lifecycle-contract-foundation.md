# Session 2026-08-04 — lifecycle contract foundation

## Authority and scope

- governing issue: #135;
- accepted design: RFC-0023 at `7bad329a69d84c58ef5c8de082b17ebeb6b8e0b3`;
- parent runtime objective: #5.

## Delivered candidate

- four closed public JSON Schemas for policy, intent, marker and receipt
  preimage;
- domain-separated JCS policy, intent and marker digests plus receipt signing
  bytes;
- public byte-exact canonical vectors;
- validated lifecycle, target, deadline, policy-successor, saga and audit
  vocabularies;
- typed `TranscriptLifecycleStore` administrative requests separated from
  ordinary `relay.Store`;
- cross-binding and exact-retry validation that rejects replacement and target
  broadening.

## Security properties

- missing, zero, infinite-equivalent, excessive and rollback policy values
  fail closed;
- marker, receipt and signature attachment bind one operation, intent,
  transcript, lifecycle result and policy digest;
- selective-redaction sequences are positive, sorted and unique;
- closed errors and audit reasons cannot carry payload, path, credential or
  provider detail;
- protocol transcript epoch zero remains supported while successor policy
  epochs must increase.

## Intentionally incomplete

No persistence adapter, SQLite mutation, payload removal, external signer,
worker, clock scheduler, backup provider, HTTP/SSE/client revision, executable,
real data, deployment, Matrix, MCP or production use is included.

## Next boundary

Review and merge this contract foundation before opening a separately bounded
SQLite lifecycle-operation increment. Merge does not authorize destructive
execution or use against any operator or user path.
