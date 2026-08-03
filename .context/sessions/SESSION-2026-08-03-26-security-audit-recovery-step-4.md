# Session: RFC-0011 fenced recovery step 4

- Date: 2026-08-03
- Governing issue: #37
- Pull request: #45
- Accepted decision: RFC-0011
- Scope: delivery step 4 only

## Outcome

Implemented signed two-database recovery manifests, persistent audit restore
fencing and explicit operational-readiness qualification. The canonical JCS
manifest binds both backup IDs, database IDs and SHA-256 digests; the complete,
sorted identity epoch-floor snapshot and wall-clock high-water; and an exact
externally signed audit checkpoint. Its signature and canonical bytes produce a
stable recovery reference.

The identity registry now supplies that recovery input atomically from admitted
state. SQLite audit schema v4 persists restore and clock fences. `OpenRestored`
hashes the backup before opening it and persists a fence before returning.
Restore validation independently verifies signer lifecycle, checkpoint
signature, ledger identity, Merkle size/root and the expected backup digest.
Normal audit mutations remain unavailable while fenced, including after a
restart.

Operational readiness is an explicit stronger gate than local structural
readiness. It verifies persisted evidence, monotonic wall time, checkpoint age,
current external signing-key trust and signer health, optional witness evidence
and configured entry/database capacity ceilings.

## Qualification

- deterministic corpus: 62 fixtures and 13 canonical vectors;
- three fixed Ed25519 signatures independently verified by OpenSSL;
- standards-schema and cross-runtime gates passed;
- JavaScript: 14 tests passed;
- full Go suite and race detector passed with NATS Server 2.12.0;
- `go vet ./...` passed;
- `govulncheck ./...` reported no reachable vulnerabilities;
- repository structure and generated-manifest gates passed.

Tests cover canonical/signature tampering, exact checkpoint and backup binding,
complete sorted identity floors, wrong backup digest, durable restore fencing,
blocked mutations, signer and witness failure, checkpoint staleness, capacity
ceilings and persistent clock-rollback fencing.

## Explicit boundary

Step 4 intentionally has no restore-completion API. A validated restore stays
fenced. The canonical `restore_fence` record vocabulary does not yet exist, so
an opaque receipt would be unverifiable and was rejected as an unsafe shortcut.
No private key, signer implementation, Vault client, credential, executable,
public administration API, cross-database transaction or runtime composition is
included. Issue #37 remains open.

## Next step

After explicit owner acceptance and merge of #45, RFC-0011 step 5 may freeze
the complete audit-record coverage, append and verify the canonical
`restore_fence` record, apply and verify identity epoch floors, and compose the
provider/runtime boundary. It must remain a separate reviewable pull request.
