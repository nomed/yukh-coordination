# Security-audit domain

This package owns the RFC-0011 canonical record, domain-separated SHA-256
preimages and exact local receipt representation. The `sqlite` subpackage owns
the separate single-node persistence adapter.

The current implementation includes RFC-0011 steps 1 and 2. It proves local
append integrity, deterministic Merkle roots and RFC 9162-style inclusion and
consistency proofs, and implements the identity audit port. It is not composed
into a process and cannot claim signed or witnessed operation. External
checkpoint signing, restore admission and witnesses are later increments.
