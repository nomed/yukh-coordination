# SQLite security-audit ledger

This package owns RFC-0011 steps 1 through 3: a separate STRICT SQLite database,
canonical records, atomic idempotent sequence allocation, local SHA-256 chain
receipts, deterministic Merkle nodes and historical inclusion/consistency
proofs. Schema v2 atomically commits each leaf, every newly completed perfect
subtree and the current root with its corresponding chain append. Schema v3
adds an immutable public authority pin, versioned signed verification-key
statements, signed checkpoints and independently verified witness
acknowledgements. No private key enters SQLite.
Receipt sequence is one-based; RFC 9162 proof leaf indexes are zero-based.

Startup and readiness rebuild expected Merkle state independently from the
canonical entries, compare every cached node, verify authority signatures and
key lifecycle, and re-check every checkpoint against its exact historical root,
chain head, predecessor and Ed25519 key. The narrow rebuild entrypoint verifies
the authoritative chain before replacing only derivable cache state.

Signing and witnessing occur through external ports; returned evidence is
verified before immutable commit. A witness acknowledgement proves only the
configured witness contract, not universal transparency. The package contains
no signer implementation, private key, restore admission or process
composition.
