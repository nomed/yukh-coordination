# Session 2026-08-04 — Verified primary payload removal

## Authority and scope

- Governing issue: #152
- Accepted design: RFC-0023
- Predecessor: merged SQLite preparation #151
- Scope: verified receipt attachment and synthetic logical primary-store
  removal only

## Candidate delivered

- signature/removal and backup/completion subinterfaces preserving the accepted
  aggregate lifecycle method set;
- public-verification-only adapter with no signer or private-key capability;
- STRICT SQLite schema v5 for signatures, digest-only removal tombstones and
  identifier non-reuse;
- exact signature attachment with domain-separated preimage verification;
- atomic selective redaction and whole-transcript primary removal;
- fail-closed redacted/deleted internal replay boundaries;
- explicit logical-removal claim with DB/WAL/SHM canary inspection.

## Qualification evidence

Generated disposable databases cover exact retry, restart, verifier failure,
changed and tampered signatures, forced transaction rollback, selective target
isolation, whole-epoch isolation, identifier non-reuse, migration, capability
separation and payload/evidence redaction. Repository structure, documentation,
vet, full race tests and the independent Node suite pass.

## Intentionally incomplete

No physical media sanitization, signer, private-key custody, backup deletion or
receipt, operation completion, worker/scheduler, clock discovery, restore
resurrection, public HTTP/SSE/client revision, executable, real data,
deployment, JetStream lifecycle, Matrix, MCP or production use is implemented
or authorized.

## Next boundary

After review and merge of #152, define and separately approve backup
obligations, recovery and completion. The aggregate lifecycle store and any
real destructive execution remain forbidden until that later boundary is
implemented and qualified.
