# SQLite security-audit ledger

This package owns RFC-0011 step 1 only: a separate STRICT SQLite database,
canonical records, atomic idempotent sequence allocation, local SHA-256 chain
receipts and complete chain verification.

It deliberately contains no Merkle tree, checkpoint signer, witness, restore
admission or process composition. A valid local chain is tamper-evident local
state, not an immutable or externally transparent log.
