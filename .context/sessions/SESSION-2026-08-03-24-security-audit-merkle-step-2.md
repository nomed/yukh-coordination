# Session: Security audit Merkle evidence step 2

- Date: 2026-08-03
- Governing issue: #37
- Accepted decision: RFC-0011
- Pull request: #41
- Branch: `agent/security-audit-merkle-step-2`

## Outcome

Implemented RFC-0011 step 2 with the exact RFC 9162 tree shape over Yukh's
domain-separated audit leaf input. The pure audit domain now computes empty,
leaf and internal hashes, historical roots, minimal inclusion paths, minimal
consistency paths and strict proof verification.

SQLite schema v2 stores only derivable perfect-subtree nodes. Each append
atomically commits the audit entry, chain head, leaf, newly completed parent
nodes, Merkle size and current root. Historical proof generation reads bounded
logarithmic paths from these immutable nodes rather than scanning the ledger.

Startup and readiness independently rebuild every expected node from the
canonical chain and compare size, root, coordinates and bytes. A narrow recovery
operation verifies that authoritative chain first and may then replace only the
derivable Merkle cache in one transaction. It cannot repair or bypass damaged
records, receipts or chain links.

## Boundary

This increment adds no signed checkpoint, signing key, witness, export,
restore admission, public route, executable or runtime composition. Tree heads
are unsigned local evidence and are not called transparency checkpoints.

## Evidence

- an independently generated Python vector freezes seven Yukh leaf hashes,
  roots for sizes zero through seven, four inclusion paths and three
  consistency paths;
- Go recomputes and verifies every independent vector byte;
- pure and SQLite-backed proofs cover empty, singleton, power-of-two, odd and
  unbalanced trees plus every prefix up to nineteen leaves;
- wrong roots, mutated, truncated, extended and out-of-range proofs fail;
- schema v1 migrates transactionally and rebuilds nodes for existing entries;
- concurrent append remains gap-free with Merkle size equal to chain size;
- missing, changed or extra nodes and wrong roots fail readiness;
- cache rebuild repairs derivable state but refuses authoritative chain damage.

## Next increment

After owner acceptance, RFC-0011 step 3 may define and implement external
Ed25519 checkpoint signing, verification-key lifecycle and the witness/export
interfaces. Restore admission and runtime composition remain later steps.
