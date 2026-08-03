# RFC-0011: Security audit ledger

- Status: Accepted
- Authors: Nomed, Codex
- Created: 2026-08-03
- Decider: project owner
- Governing issue: #37
- Governing pull request: #38
- Depends on: RFC-0002, RFC-0008, RFC-0009, RFC-0010

## Decision

Approve the exact first profile for a separate, durable security-audit ledger:

1. canonical closed audit records and idempotent append receipts;
2. a STRICT SQLite database with an immediate domain-separated hash chain;
3. RFC 9162-style Merkle commitments and externally signed checkpoints;
4. explicit verification, backup, restore, key lifecycle and readiness rules;
5. mandatory audit coverage for identity and security operations.

Acceptance authorizes implementation in `yukh-coordination`. It does not
authorize a public administration API, a policy engine, an executable, or an
audit implementation in the event or identity databases.

## Why this exists

RFC-0010 deliberately introduced a mandatory `Auditor` port without pretending
that a fake or process log was security evidence. The relay now needs a real
provider that can prove which security decision it recorded, in which order,
and whether the evidence observed later is consistent with an earlier trusted
checkpoint.

The first profile is a **tamper-evident security-audit ledger**. It is not
tamper-proof. A hash chain cannot by itself detect replacement of the entire
database. A Merkle tree cannot by itself stop a compromised log from presenting
different valid trees to different observers. Those claims require a trusted
checkpoint outside the relay failure domain and, for split-view detection, an
independent witness or cross-log publication.

## Invariants

- Security evidence is not stored in protocol events, the event database, NATS,
  the identity database, stderr or application logs.
- An allow or deny covered by a mandatory audit port is not returned before its
  audit append commits.
- One operation ID identifies one exact canonical record forever. An exact retry
  returns the same receipt; different bytes conflict.
- Sequence allocation, canonical record, record digest, predecessor digest and
  new chain head commit atomically in one audit-database transaction.
- A receipt is exposed only after commit. An uncertain commit is retried with
  the same operation ID and bytes; no replacement is created.
- Audit rows are never updated or deleted in the first profile.
- Private signing keys never enter SQLite, configuration, environment variables,
  command arguments, logs, receipts or exports.
- A locally valid chain is not described as externally anchored. A signed local
  checkpoint is not described as independently witnessed.
- Restore remains fenced until the restored evidence has been checked against an
  acceptable checkpoint held outside the restored database.

## Component and repository boundary

The implementation belongs in `yukh-coordination` because it records relay
security decisions and satisfies the relay's mandatory audit port. It does not
belong in `yukh-mcp`, `yukh-projects` or `nomed.github.io`.

The adapter will live under `internal/relay/audit/sqlite`. It may implement the
existing identity `Auditor` port, but the audit package owns persistence,
canonicalization, receipts, proofs and checkpoints. Moving shared audit value
types out of the identity package is allowed only when it removes dependency
direction problems; no public package is introduced by this RFC.

## Canonical audit record

The stored record is UTF-8 JSON canonicalized with RFC 8785 JCS. Duplicate
members, invalid UTF-8, non-integer numbers, values outside the JSON safe-integer
range, unknown members and unbounded strings are rejected before persistence.
Times use UTC RFC 3339 with exactly millisecond precision. Digests and binary
identifiers use unpadded base64url. UUIDs use lowercase canonical text.

Every record contains:

- `profile`: exactly `yukh-security-audit/v1`;
- UUIDv7 `operation_id`;
- closed `operation_kind`;
- closed `outcome`: `allow`, `deny` or `unavailable`;
- closed reason code valid for that operation and outcome;
- `decision_time`;
- only the operation-specific trusted references defined below.

The initial operation kinds are:

- `bootstrap`;
- `session_authentication`;
- `revocation`;
- `jwks_refresh`;
- `restore_fence`;
- `audit_checkpoint`;
- `audit_key_lifecycle`.

Applicable optional fields are tenant ID, derived principal ID, participant
instance ID, epoch, verified DPoP-thumbprint digest, activation reference,
authority reference, JWKS-set digest, checkpoint reference and signing-key
reference. Each operation kind has a closed field matrix; an inapplicable field
is an error rather than `null`.

Records exclude bearer/session tokens, DPoP proofs, JWT or JWK bytes, external
subjects, token/proof `jti`, request or response bodies, arbitrary provider
errors, stack traces, network locations and credentials. Human explanation is
derived from reason codes outside the canonical record.

## Immediate append and chain receipt

The database owns a random UUIDv7 `ledger_id`. The genesis digest is:

```text
SHA-256("yukh-coordination:audit-chain-genesis:v1\n" || ledger_id_bytes)
```

For entry `n`, where `n` is a positive JSON-safe integer:

```text
record_digest = SHA-256(
  "yukh-coordination:audit-record:v1\n" || canonical_record
)

chain_digest = SHA-256(
  "yukh-coordination:audit-chain:v1\n" ||
  uint64be(n) || previous_chain_digest || record_digest
)
```

The durable receipt contains profile, ledger ID, sequence, operation ID, record
digest, previous chain digest and chain digest. Its canonical bytes are frozen
by conformance fixtures. The receipt is evidence of a committed local append;
it is not individually signed and does not claim external anchoring.

An exact operation-ID retry compares canonical bytes, not merely the digest. A
different record for the same ID returns conflict. Digest collision detection,
sequence exhaustion, metadata mismatch or indeterminate commit makes the audit
provider unavailable and therefore closes admission.

## SQLite profile and schema ownership

The audit database is a dedicated file with a unique validated path. It uses
the same disciplined SQLite profile as the accepted stores: WAL, `FULL`
synchronous mode, foreign keys, bounded busy timeout, one open connection,
STRICT tables, `user_version`, explicit migrations and `BEGIN IMMEDIATE` for
writes.

The first schema owns:

- singleton ledger metadata and current chain head;
- immutable audit entries and exact canonical bytes;
- Merkle nodes required to rebuild and serve proofs;
- signed checkpoints and their key references;
- public verification-key lifecycle metadata;
- external-anchor acknowledgements and restore-fence state.

Schema triggers abort update and delete attempts on entries and checkpoints.
They are defence in depth, not a claim that a host administrator cannot replace
the file or executable. Cached Merkle nodes are derivable; entries, receipts and
signed checkpoints are authoritative. A cache rebuild must reproduce the exact
root before readiness can become true.

## Merkle commitments

Each committed chain receipt contributes one leaf in sequence order:

```text
leaf_input =
  "yukh-coordination:audit-merkle-leaf:v1\n" ||
  uint64be(sequence) || chain_digest

leaf_hash = SHA-256(0x00 || leaf_input)
node_hash = SHA-256(0x01 || left_hash || right_hash)
```

Tree construction, inclusion proofs and consistency proofs follow the Merkle
tree rules of RFC 9162. Domain separation between leaves and internal nodes is
mandatory. Golden fixtures freeze empty, one-leaf, odd-width and multi-level
trees and proof verification.

Merkle maintenance may complete in the append transaction or through a durable
catch-up state. If it lags, receipts may still be returned because their chain
state committed atomically, but checkpoint creation and checkpoint-dependent
readiness remain unavailable until the exact prefix is caught up. No checkpoint
may skip, reorder or synthesize an entry.

## Signed checkpoints and witnesses

A checkpoint binds:

- profile and ledger ID;
- exact tree size and root hash;
- chain head at that tree size;
- issue time;
- signing algorithm and stable public key ID;
- predecessor checkpoint reference when present.

The signature input is the RFC 8785 canonical checkpoint without the signature,
prefixed by `yukh-coordination:audit-checkpoint:v1\n`. The first provider uses
the RFC-0008 external Vault Transit Ed25519 signer. Its non-exportable private
key remains outside the relay; the returned signature is locally verified before
the checkpoint is committed. Algorithm or key substitution is forbidden.

Normal rotation leaves old checkpoints valid under their declared key windows.
Compromise publishes an affected interval; cryptographically valid checkpoints
in that interval verify as `indeterminate`, not trusted. The verification key
set and lifecycle statements are themselves versioned signed evidence.

The single-node profile distinguishes three states:

1. `local`: chain and Merkle root verify inside the database;
2. `signed`: a checkpoint signature verifies with an accepted key;
3. `witnessed`: the exact signed checkpoint or its digest has an independently
   verifiable acknowledgement outside the relay failure domain.

Only the third state detects restoration behind the last witness and supplies a
basis for split-view comparison. Even then, a single witness is not universal
transparency; the export format permits later cross-logging or multiple
witnesses without changing entry bytes.

## Failure, recovery and restore

On startup the provider validates schema, metadata and the latest accepted
external checkpoint, then verifies the checkpoint prefix and every subsequent
chain link and Merkle update. Bounded cached state may accelerate this process,
but a cache cannot override canonical evidence. Corruption, missing entries,
wrong predecessor, inconsistent roots, unknown keys, stale required witness or
clock rollback keeps readiness false.

Database backup alone cannot prove freshness. The backup workflow produces a
signed recovery manifest after both the identity and audit backups exist. The
manifest binds their database IDs, backup digests, audit checkpoint, identity
epoch high-water evidence, creation time and signer key. It does not pretend
that two SQLite files shared one atomic transaction.

Restore starts fenced. It verifies backup digests, database identities, signer
lifecycle, audit chain/tree and a checkpoint at least as new as the restored
audit prefix. It then loads identity epoch floors monotonically, appends a
`restore_fence` audit record and only afterwards admits authentication. A
missing, older, wrong-database, compromised-key or unverifiable checkpoint
fails closed.

## Retention and confidentiality

The first profile deletes no individual audit rows. Capacity limits warn and
then fail closed before filesystem exhaustion. A future ledger rollover must
close the old ledger with a witnessed checkpoint and open the new ledger with a
signed reference to it; it cannot silently prune history.

Exports are bounded, canonical and contain no more identity material than the
ledger. Filesystem permissions, encrypted storage and backup access controls are
deployment obligations. Derived identifiers remain sensitive and are not sent
to NATS or ordinary logs.

## Readiness and observability

Audit readiness requires:

- valid database profile, schema and unique database identity;
- a fully verified chain and Merkle state through the committed head;
- an accepted current signing key and functioning signer when a checkpoint is
  required;
- no unresolved commit, signature, corruption, restore or clock fence;
- an external checkpoint within the configured maximum age for profiles that
  claim witnessed operation.

Metrics expose bounded counts, sequence lag, checkpoint age and reason-code
classes. They never expose canonical records, identifiers, digests usable as
cross-system correlators, credentials or provider diagnostics.

## Qualification evidence

Implementation is not complete without deterministic evidence for:

- canonical JSON and receipt bytes across implementations;
- exact idempotent retry and same-ID/different-bytes conflict;
- concurrent gap-free append and crash at every transaction boundary;
- commit-uncertain recovery without replacement operations;
- byte mutation, reorder, duplicate, deletion and suffix truncation;
- RFC 9162-style roots, inclusion proofs and consistency proofs;
- checkpoint signing, verification, rotation, retirement and compromise;
- signer outage and locally rejected malformed or substituted signatures;
- rollback detected against an external checkpoint;
- simulated split views detected by witness comparison;
- backup/recovery manifest and every restore-fence negative;
- capacity, clock rollback, cache rebuild and migration failure;
- absence of forbidden secrets and arbitrary text;
- race, fuzz, subprocess crash, vet and vulnerability scanning.

## Delivery sequence

1. Freeze canonical records, receipt fixtures and the STRICT schema; implement
   atomic idempotent append and complete chain verification.
2. Implement Merkle state, inclusion/consistency proofs and deterministic
   rebuild.
3. Implement external Ed25519 checkpoint signing, verification-key lifecycle
   and witness/export interfaces.
4. Implement backup recovery manifests, restore fencing and operational
   readiness.
5. Compose the real provider and extend mandatory coverage to JWKS, revocation,
   checkpoint, key-lifecycle and restore operations.

Each step is a separately reviewable pull request. No step weakens the mandatory
audit port while later steps are incomplete.

## Alternatives rejected

### Plain application or structured logs

Rejected because operators can rotate, truncate or rewrite them and they do not
provide exact idempotent receipts or durable ordering.

### A hash chain without checkpoints

Rejected as the final design because it cannot prove that the whole file was
not replaced or truncated to an earlier internally valid state and provides no
efficient prefix-consistency proof.

### A Merkle tree without immediate chain receipts

Rejected for the first profile because mandatory decisions need a small exact
commit receipt immediately, while checkpoint construction may lag. The chain
also gives simple sequential recovery evidence; the Merkle layer supplies
efficient set and prefix proofs.

### Sign every entry

Rejected because it places signer availability and cost on every decision while
still not preventing a compromised signer from producing split views. Atomic
chain receipts plus periodic signed roots preserve the required evidence with a
clearer failure boundary.

### Put audit in the identity or event transaction

Rejected because security audit has different access, retention, recovery and
compromise boundaries. SQLite multi-file attachment would not create the honest
independent durability contract required by RFC-0010.

### Publish private records to a public transparency service

Rejected for the first profile because audit records contain sensitive derived
identity and operational evidence. The export boundary can anchor a checkpoint
digest externally without disclosing entries.

### Claim transparency from one signed local tree

Rejected because a log can sign or serve inconsistent views. The system uses
the narrower terms `tamper-evident`, `signed` and `witnessed` and exposes
evidence sufficient for independent comparison.

## Normative and informative references

- RFC 8785, JSON Canonicalization Scheme.
- RFC 9162, Certificate Transparency Version 2 Merkle tree and proof
  construction; Yukh does not adopt its certificate-specific wire protocol.
- FIPS 186-5, digital signature requirements and EdDSA profile.
- NIST SP 800-92, log-management operational guidance.
- Sigstore Rekor is an informative operational precedent for externally
  verifiable transparency logs, not a dependency or security authority for this
  profile.
