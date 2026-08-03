# Session 2026-08-03 — transcript lifecycle and retention RFC

## Authority and scope

- Governing issue: #5
- Bounded increment: #133
- Proposed decision: RFC-0023
- Prerequisite: RFC-0008 mandatory executable gate

## Delivered candidate

- explicit finite retention policy bound before first append;
- independent lifecycle/completeness and monotonic epoch semantics;
- separate administrative port outside ordinary `relay.Store`;
- signed-marker-before-removal, idempotent destructive saga;
- per-domain backup-deletion obligations and receipts;
- clock rollback, crash, restore and resurrected-payload fencing;
- explicit pre-release HTTP/client read revision for non-active transcripts;
- roles, redacted audit evidence, qualification and rollback boundaries.

## Critical conclusion

The relay executable cannot be assembled honestly by merely wiring the existing
runtime. RFC-0008 forbids event admission until this lifecycle boundary is
accepted, implemented and qualified. Database TTL, silent deletion and adding
destructive methods to `relay.Store` are rejected.

## Verification

- alignment with RFC-0001 lifecycle/completeness semantics;
- alignment with RFC-0002 mandatory finite retention;
- alignment with RFC-0008 binary authorization gate;
- repository and documentation structure checks;
- `git diff --check` and redaction review.

## Intentionally incomplete

No schema, port, SQLite migration, worker, executable, deployment or destructive
operation is implemented. Matrix, MCP, JetStream lifecycle and production use
remain outside this increment.

## Next boundary

Explicit owner acceptance of RFC-0023 authorizes only a separately reviewed
implementation sequence: schemas/port, SQLite lifecycle transaction, worker
saga/recovery and hermetic qualification. It does not authorize real deletion
or relay deployment.
