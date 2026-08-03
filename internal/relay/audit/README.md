# Security-audit domain

This package owns the RFC-0011 canonical record, domain-separated SHA-256
preimages and exact local receipt representation. The `sqlite` subpackage owns
the separate single-node persistence adapter.

The current implementation is step 1 only. It proves local append integrity and
implements the identity audit port, but it is not composed into a process and
cannot claim signed or witnessed operation. Merkle proofs, external checkpoint
signing, restore admission and witnesses are later RFC-0011 increments.
