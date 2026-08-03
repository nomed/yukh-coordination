# SQLite security-audit ledger

This package owns RFC-0011 steps 1 through 4: a separate STRICT SQLite database,
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

Step 4 intentionally exposes no restore-completion API: a validated backup
remains fenced across restarts. Step 5 must define and persist the canonical
`restore_fence` audit record, apply the identity epoch floors, verify both facts
and only then perform the sole transition back to admitted operation.
`OperationalReady` verifies persisted evidence,
wall-clock monotonicity, checkpoint freshness, active signing-key health,
optional witness evidence and explicit entry/database capacity ceilings. The
simpler `Ready` method remains local structural verification until step 5
supplies mandatory operational policy and external probes.
