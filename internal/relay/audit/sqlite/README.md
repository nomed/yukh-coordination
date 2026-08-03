# SQLite security-audit ledger

This package owns RFC-0011 steps 1 and 2: a separate STRICT SQLite database,
canonical records, atomic idempotent sequence allocation, local SHA-256 chain
receipts, deterministic Merkle nodes and historical inclusion/consistency
proofs. Schema v2 atomically commits each leaf, every newly completed perfect
subtree and the current root with its corresponding chain append.
Receipt sequence is one-based; RFC 9162 proof leaf indexes are zero-based.

Startup and readiness rebuild expected Merkle state independently from the
canonical entries and compare every cached node. The narrow rebuild entrypoint
verifies the authoritative chain before replacing only derivable cache state.

It deliberately contains no checkpoint signer, witness, restore admission or
process composition. A valid local tree is tamper-evident local state, not an
immutable or externally transparent log.
