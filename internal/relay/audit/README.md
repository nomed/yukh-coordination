# Security-audit domain

This package owns the RFC-0011 canonical record, domain-separated SHA-256
preimages and exact local receipt representation. The `sqlite` subpackage owns
the separate single-node persistence adapter.

The current implementation includes RFC-0011 steps 1 through 3. It proves local
append integrity, deterministic Merkle roots and RFC 9162-style proofs, and
defines canonical Ed25519 checkpoints, authority-signed verification-key
lifecycle statements, bounded exports and external witness ports.

Checkpoint private keys and witness authority remain outside this package. The
package freezes external signer and verifier contracts and verifies returned
signatures locally; it does not contain a Vault client or compose an operated
process. Restore admission and runtime composition are later increments.
