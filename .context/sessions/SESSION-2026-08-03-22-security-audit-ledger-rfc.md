# Session: Security audit ledger design

- Date: 2026-08-03
- Governing issue: #37
- Proposed decision: RFC-0011
- Branch: `agent/security-audit-ledger-rfc`

## Outcome

Defined the proposed first durable security-audit profile without implementing
it. The design keeps audit evidence in its own SQLite failure domain, provides
an atomic idempotent chain receipt for every mandatory decision and adds Merkle
proofs plus externally signed checkpoints for efficient independent
verification.

The design deliberately does not call an internally consistent database
immutable or transparent. Whole-database rollback requires a checkpoint held
outside the restored node; split-view detection requires comparison through an
independent witness or cross-log. The first implementation is therefore named a
tamper-evident audit ledger with explicit local, signed and witnessed states.

## Boundary

This session changes documentation only. It adds no database, signer, public
API, policy engine, listener, configuration or executable. Implementation
starts only after RFC-0011 is accepted and remains in `yukh-coordination`.

## Next review

Review the canonical record field matrix, chain/Merkle preimages, external
checkpoint claim and recovery-manifest boundary. If accepted, implement step 1
only: schema, canonical fixtures and atomic chain append.
