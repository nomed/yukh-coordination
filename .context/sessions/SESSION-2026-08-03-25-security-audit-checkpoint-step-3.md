# Session: RFC-0011 signed checkpoint step 3

- Date: 2026-08-03
- Governing issue: #37
- Pull request: #42
- Accepted decision: RFC-0011
- Scope: delivery step 3 only

## Outcome

Implemented the provider-neutral signed-checkpoint domain and SQLite evidence
boundary. A checkpoint binds the exact ledger ID, current non-empty tree size,
historical Merkle root, chain head, millisecond issue time, Ed25519 key ID and
predecessor checkpoint reference. Its JCS bytes use the RFC-0011 domain prefix;
the signature and canonical bytes produce a stable checkpoint reference.

The external signer selects one already registered key and receives only the
exact frozen preimage. The returned raw Ed25519 signature is checked locally
against the authority-signed verification-key statement before any checkpoint
row commits. An append racing the external signing call invalidates the
candidate instead of signing a stale or synthetic prefix.

Schema v3 stores only public trust material: one immutable authority public-key
pin, append-only versioned key lifecycle statements, immutable checkpoints and
verified witness acknowledgements. Private keys, Vault coordinates and
credentials never enter SQLite. Startup independently verifies authority
signatures, statement evolution, historical roots and chain heads, checkpoint
predecessors, Ed25519 signatures and witness acknowledgement digests.

Normal key rotation preserves older checkpoint validity. Retirement uses an
exclusive boundary. A declared compromise interval changes an otherwise valid
checkpoint from `trusted` to `indeterminate`; such a checkpoint may be exported
as evidence but cannot receive a new witness acknowledgement through the
ledger.

The export is bounded canonical JSON carrying the exact checkpoint signature
and signed key statement. The witness boundary accepts only a closed canonical
envelope and requires a provider-specific verifier before immutable storage. A
single acknowledgement is not described as universal transparency.

## Qualification

- deterministic corpus: 62 fixtures and 12 canonical vectors;
- fixed receipt and checkpoint Ed25519 signatures independently verified by
  OpenSSL using the RFC 8032 test-vector key;
- standards-schema and cross-runtime gates passed;
- JavaScript: 14 tests passed;
- full Go suite and race detector passed with NATS Server 2.12.0;
- `go vet ./...` passed;
- `govulncheck ./...` reported no reachable vulnerabilities;
- repository structure and generated-manifest gates passed.

Tests cover exact key-statement retry, authority substitution, signer outage,
malformed and substituted signatures, head movement during signing, restart,
schema migration, checkpoint tampering, predecessor chaining, normal rotation,
retirement, compromise classification, bounded export and witnessed evidence.

## Explicit boundary

This increment adds no Vault client, signer credentials, executable, public
administration API, backup recovery manifest, restore admission, operational
readiness policy or runtime composition. RFC-0011 steps 4 and 5 remain
unimplemented. Issue #37 therefore remains open.

## Next step

After explicit owner acceptance and merge of #42, RFC-0011 step 4 may implement
backup recovery manifests, restore fencing and operational readiness. It must
remain a separate reviewable pull request; provider/runtime composition remains
step 5.
