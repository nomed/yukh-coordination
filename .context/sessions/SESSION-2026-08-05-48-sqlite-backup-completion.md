# Session: SQLite backup and completion persistence

- Date: 2026-08-05
- Governing issue: #165
- Governing RFC: RFC-0023
- Base: current `main` after PR #157
- Authority: owner-approved implementation of the reviewed #165 scope

## Outcome

The authority-neutral lifecycle contract now includes the exact canonical
`BackupObligationSet`, its domain-separated digest and exact-retry validation,
the `BindBackupObligations` administrative method and the narrow public
`CompletionAuditVerifier` capability.

SQLite schema version 6 adds immutable obligation-set and obligation rows,
globally non-reusable append-only custodian receipts and one immutable
completion-evidence identity per operation. A dedicated adapter implements only
`TranscriptLifecycleBackupCompletionStore`. It advances `payload_removed` to
`backups_pending` only from an exact three-obligation request, records only
publicly verified receipts and completes only from explicit evidence after
public audit verification. External verification always precedes the SQLite
write transaction; the transaction reloads and byte-compares its preflight
snapshot without external I/O.

Synthetic qualification covers exact and concurrent retry, migration v5 to v6,
restart, changed-set conflict, receipt verification unavailability, durable
failure/later-attempt incidents, mixed ordered findings, audit unavailability,
forced rollback and compile-time capability segregation. Full Go race, vet,
Node conformance and repository/documentation structure checks are required
before delivery.

## Explicit exclusions

No backup provider, deletion execution, audit write or checkpoint creation,
signer/private key, worker, scheduler, restore execution, physical sanitization,
HTTP/SSE/client change, executable composition, real data, deployment,
JetStream lifecycle, Matrix, MCP or production authority is introduced.

## Review correction

Formal review of draft PR #168 required exact concurrent convergence for
receipt and completion retries, complete validation of canonical evidence
against every redundant SQLite column, schema-enforced immutability, an
independent public obligation-set schema/vector and rollback/corruption tests
at the remaining write boundaries. The corrected candidate adds all five
controls. A `completed` operation without its exact canonical completion row,
or any drift between the obligation set and stored evidence, is now bounded
corruption rather than recoverable success.

## Next boundary

Publish a review pull request linked to #165 after complete qualification. A
later worker/provider increment requires separate owner review and approval and
may not reinterpret or bypass this evidence contract.
