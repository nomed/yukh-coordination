# SQLite security-audit ledger

This package owns the RFC-0011 SQLite provider: a separate STRICT SQLite database,
canonical records, atomic idempotent sequence allocation, local SHA-256 chain
receipts, deterministic Merkle nodes and historical inclusion/consistency
proofs. Schema v2 atomically commits each leaf, every newly completed perfect
subtree and the current root with its corresponding chain append. Schema v3
adds an immutable public authority pin, versioned signed verification-key
statements, signed checkpoints and independently verified witness
acknowledgements. No private key enters SQLite. Schema v4 adds persistent
admitted/restore/clock fences and immutable accepted recovery manifests.
Receipt sequence is one-based; RFC 9162 proof leaf indexes are zero-based.

`OpenRestored` hashes a regular non-symlink backup before SQLite can modify it
and fences it immediately. A verified restore plan binds that exact digest,
both database identities, the complete sorted identity epoch floors and an
exact signed checkpoint. The first operational profile freezes writes around
checkpoint and backup, so the backup and checkpoint roots are equal; it does
not pretend that two SQLite files share a transaction.

Startup and readiness rebuild expected Merkle state independently from the
canonical entries, compare every cached node, verify authority signatures and
key lifecycle, and re-check every checkpoint against its exact historical root,
chain head, predecessor and Ed25519 key. The narrow rebuild entrypoint verifies
the authoritative chain before replacing only derivable cache state.

Signing and witnessing occur through external ports; returned evidence is
verified before immutable commit. A witness acknowledgement proves only the
configured witness contract, not universal transparency. The package contains
no signer implementation, private key or process composition.

Verification-key installation commits its closed lifecycle record in the same
ledger transaction. Checkpoint creation precomputes a closed checkpoint record,
signs the tree that includes it, then atomically commits both record and signed
checkpoint after proving the head did not move. This avoids asking a checkpoint
to contain its own reference.

`CommitRestore` is the only audit restore-completion transition. In one SQLite
transaction it appends the canonical manifest-bound `restore_fence` record,
persists the signed recovery manifest and admits the audit ledger. Identity
remains independently fenced until it consumes that exact receipt. The runtime
coordinator orders and safely resumes this saga without claiming a transaction
across SQLite files. `OperationalReady` verifies persisted evidence,
wall-clock monotonicity, checkpoint freshness, active signing-key health,
optional witness evidence and explicit entry/database capacity ceilings. The
simpler `Ready` method intentionally remains local structural verification and
is not the runtime adapter. `OperationalProvider` is the runtime-facing
identity audit adapter and always uses the stronger gate; this does not claim
that an operated deployment has passed production qualification.
