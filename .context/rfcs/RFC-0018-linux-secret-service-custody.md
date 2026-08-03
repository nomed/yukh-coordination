# RFC-0018: Linux Secret Service custody composition

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #68
- Governing architecture: RFC-0013 and RFC-0014

## Decision requested

Select the first concrete local custody composition for the RFC-0014 client
ports. One explicitly configured Freedesktop Secret Service item holds a
random profile root key. A dedicated local SQLite database holds only
authenticated-encrypted session records and P-256 private-key records and owns
exact transactional revisions. The software signer decrypts one private key
only for one bounded signing operation.

Secret Service alone is explicitly rejected as a persistent Yukh
`CredentialStore`. Its `CreateItem(replace=true)` operation replaces an item by
matching lookup attributes; it does not compare an exact prior revision. Its
`Modified` property is a timestamp, not a conditional mutation token. Inventing
a revision above those operations would violate RFC-0014.

Acceptance authorizes a separately reviewed implementation of this composition
and deterministic conformance tests. It does not authorize an external-token
source, bootstrap orchestration, executable wiring, credentials, user data,
deployment, remote adapters or a selectable end-to-end custody profile.

## Closed composition

The adapter is constructed from one closed, non-secret configuration:

- an opaque profile identifier generated independently of user, repository,
  tenant and project names;
- an already-established caller-owned D-Bus connection, the exact service
  name, collection object path and root-item schema;
- an absolute SQLite path beneath a caller-owned private directory;
- fixed operation, prompt and shutdown policy values selected by this RFC.

It connects only to the caller's D-Bus session bus and the configured Secret
Service. It never discovers a desktop service, changes collection aliases,
tries a second collection, reads provider environment variables or falls back
to files, plaintext, another keyring or an in-memory profile.

The adapter never resolves a bus address. Runtime composition must establish
and authenticate the exact session-bus connection and pass that live
connection into the constructor. In particular the adapter does not read
`DBUS_SESSION_BUS_ADDRESS`, inspect well-known runtime directories or open a
default bus. Connection acquisition and executable configuration remain a
separate gate.

The composition implements `CredentialStore` and `ProofSignerStore`. It does
not implement `ExternalTokenSource`. A future bootstrap composition must bind
all three ports explicitly before the profile can be selected by an executable.

## Security boundary

This is a single-user, single-host desktop profile. Secret Service protects one
root key at rest according to the selected service and collection policy.
SQLite supplies transactional state, not secret custody. Confidentiality and
integrity of every SQLite payload derive from the Secret Service root key and
AEAD validation.

The profile does not claim isolation from a process that can act as the same
login user, control that user's session bus, debug the client process, replace
the configured database, or administer the selected Secret Service. The
filesystem and D-Bus constraints reduce accidental disclosure and cross-user
access; they do not turn a desktop keyring into an HSM.

Secret Service lookup attributes, labels, object paths and timestamps are
treated as public metadata. They contain no profile name, participant ID,
tenant, repository, endpoint, token, key coordinates or provider identity.
The only correlation value is the opaque profile identifier.

## Root-key item

The root item contains exactly 32 random bytes and the fixed content type
`application/octet-stream`. Its lookup attributes are fixed schema identifiers
plus the opaque profile identifier. The item label is generic and contains no
adopter data.

Provisioning searches only the configured collection with the complete exact
attribute set:

- zero matches permits creation with `replace=false`;
- one match opens that exact item;
- more than one match is an ambiguous-store failure;
- a returned item whose attributes, content type or secret length differ is a
  corrupt-store failure.

The adapter never calls `CreateItem` with `replace=true`, changes the root item
or rotates it in v1. A missing item after encrypted records exist is terminal;
the adapter never creates a replacement key because that would make existing
state undecryptable while appearing to be a new valid identity.

If root creation returns an ambiguous transport result, the adapter performs
one bounded exact search on a new Secret Service session. Exactly one valid
item reconciles success; zero or multiple items fail closed. No retry creates a
second root item.

## Secret transfer and prompt policy

The Secret Service session is bound to the caller-provided D-Bus connection and
is closed on completion. The implementation must use one transfer algorithm
selected and qualified for the exact service implementation. It cannot retry
with `plain` after negotiation failure. Transfer encryption is defense in
depth; the Secret Service specification does not make it an authenticated
channel against an active same-session attacker.

The adapter never invokes a Secret Service prompt. A locked item or collection,
an operation returning a prompt object, or a service that requires UI fails
with the stable custody-unavailable class. This preserves the RFC-0013
non-interactive command contract and prevents an agent from causing ambient
desktop UI. Unlocking remains an explicit human action outside Yukh.

The service may relock at any time. Every read is therefore independently
fallible; no successful earlier probe implies later availability.

## Encrypted SQLite envelope

The database has independent schema-version metadata and two bounded logical
tables:

1. one current encrypted session record per opaque profile identifier;
2. immutable encrypted signer records keyed by a random 128-bit key reference.

The root key is expanded with HKDF-SHA-256 into independent 256-bit AEAD keys
for session and signer domains. The salt binds the database schema and opaque
profile identifier; the info value binds the exact object domain.
XChaCha20-Poly1305 uses a fresh cryptographically random 192-bit nonce for every
encryption. AES-GCM and nonce-size negotiation are not part of this profile.

The database metadata counts every successfully committed encryption under the
root key. Increment and ciphertext commit occur in the same transaction. The
profile permits at most 2^32 committed encryptions under one root key and then
fails closed before encryption. V1 has no automatic root rotation or counter
reset; reaching the limit requires a separately designed migration. The count
is a conservative operational bound, not the source of nonce uniqueness.

Canonical associated data binds at least:

- schema version;
- opaque profile identifier;
- object kind;
- random object identifier;
- exact record revision;
- proof-key reference for a session record.

Ciphertext, nonce, associated-data fields and revision are committed in the
same SQLite transaction. Decryption or canonical-decoding failure is corruption
and never absence. Plaintext session tokens and private keys are never written
to SQLite, WAL, temporary tables, diagnostics or generic serialization.

Session plaintext is the closed RFC-0014 `SessionRecord`. Signer plaintext is
one strictly parsed PKCS #8 P-256 private key whose derived public JWK and
thumbprint are recomputed after every open. Unknown fields, algorithms, curves,
versions or non-canonical encodings fail closed.

## Revisions and compare-and-set

Each successful session mutation generates a fresh random 128-bit revision.
The opaque encoded revision is returned through the neutral `Revision` value
and is always redacted.

`Save` runs one SQLite write transaction:

- absent creation inserts only if no profile row exists;
- replacement updates only where the stored revision equals the exact expected
  revision;
- the candidate ciphertext and new revision become visible atomically.

`Delete` removes only where the exact expected revision matches. Zero affected
rows is a credential conflict, whether the row is absent or changed. No
read-then-write sequence outside the transaction implements CAS.

SQLite busy, I/O, full-disk, durability or commit ambiguity returns a bounded
store failure. The caller may perform a new `Load` to observe authoritative
state but the mutation call never converts ambiguity into success. Bootstrap
reports success only after RFC-0014's exact load/open/binding verification.

## Signer lifecycle

`ProvisionP256` obtains the root key, opens one write transaction and resolves
the one active signer reference for the profile. If absent it generates a P-256
key, validates it, encrypts it under a fresh random reference and inserts it
with a unique active-profile constraint. A uniqueness conflict is reconciled by
opening the committed exact signer; it never creates or selects a second key.

`Open` accepts only a closed random key reference, loads exactly one immutable
row, decrypts and validates the key, and returns a signer that cannot export
private material. Each `SignES256` call:

1. bounds and copies the exact signing input;
2. loads the root key and decrypts the exact signer record;
3. signs once using P-256 and SHA-256;
4. converts to fixed-width JOSE `R || S`;
5. verifies the signature locally against the derived public key;
6. erases owned plaintext buffers where the Go runtime permits and releases
   all references before returning.

No root or private key is cached across operations. This limits lifetime but
does not claim guaranteed erasure from a garbage-collected process.

`Retire` is allowed only for an exact signer created by the current failed
bootstrap attempt and only when one transaction proves that no session row
references it. It deletes the encrypted signer row; it does not delete or
rotate the Secret Service root item. General rotation remains outside v1.

## Filesystem and process rules

The configured database path is absolute, clean and beneath an existing
caller-owned directory with no group or other permissions. The adapter rejects
symlinks for the directory and existing database path, applies a restrictive
umask during creation and verifies the database, WAL and shared-memory files
remain owned by the effective user with mode `0600`.

SQLite is opened in WAL mode with foreign keys enabled, bounded busy handling,
no network filesystem support and durability settings fixed by the
implementation qualification. The adapter accepts no caller-supplied SQL,
pragma, DSN query or extension.

Restoring or replacing the database with an older valid encrypted copy is a
rollback that this local profile cannot detect: Secret Service supplies custody
but no monotonic compare-and-set anchor. Database backup, restore, copying and
rollback recovery are therefore unsupported in v1. A restored session may be
rejected by the relay or expire, but the adapter cannot claim that as local
rollback detection. A future backup profile requires a separately accepted
anti-rollback authority and migration contract.

Two compliant processes may open the same profile. SQLite transactions and
exact revisions serialize mutations; stale writers receive conflict. Sharing
the same profile across hosts is forbidden and unsupported.

## Failures and observability

Stable outcomes distinguish only invalid configuration, unavailable/locked
custody, conflict, corruption and internal failure. Provider error strings,
D-Bus names beyond the fixed service class, object paths, filesystem paths,
SQLite diagnostics, attributes, ciphertext, nonces, revisions, profile IDs,
tokens and key material are absent from public errors and metrics.

The adapter emits no secret values or adopter identifiers to logs, traces,
session records or GitHub evidence. Tests may use synthetic opaque identifiers
only.

## Qualification gate

Implementation is not qualified until deterministic tests and real-service
integration evidence prove:

- root item zero/one/multiple, malformed and ambiguous-create outcomes;
- locked collection and every prompt-producing path fail without calling
  `Prompt`;
- absence of provider discovery and plaintext fallback;
- encrypted SQLite, WAL and shared-memory secret scanning;
- AEAD domain, nonce, associated-data, revision and key-reference tampering,
  cross-domain substitution and the 2^32 encryption limit;
- absent-create, replacement and deletion CAS under concurrent processes;
- crash and commit ambiguity before, during and after SQLite commit;
- signer uniqueness, immutable references, local signature verification and
  retirement only when unreferenced;
- wrong curve, changed key, corrupt PKCS #8 and session/signer substitution;
- permission, ownership, symlink, full-disk and database-lock failures;
- bounded redacted errors and absence of secrets in formatting and output;
- restart recovery without key substitution or implicit profile sharing;
- rejection and explicit reporting of unsupported database restore and
  rollback scenarios.

Real-service evidence is required for at least GNOME Keyring and KeePassXC
Secret Service integration on supported Linux versions. Each implementation's
exact transfer algorithm, lock, prompt, persistence and delete behavior is
recorded. Passing one service does not imply qualification of another.

## Rollout gates

Acceptance permits only a separate implementation PR with synthetic test data.
After implementation qualification, separate decisions are still required for:

1. the external DPoP-bound token source;
2. bootstrap saga composition;
3. executable configuration and command wiring;
4. signer/root rotation and recovery tooling;
5. live-user migration or deployment.

## Alternatives rejected

- **Secret Service as the session database:** lacks exact-revision CAS and
  cannot meet RFC-0014 by inventing revisions from timestamps or object paths.
- **`CreateItem(replace=true)` as CAS:** replacement matches public attributes,
  not an expected immutable version.
- **Session or private key in plaintext SQLite:** makes database possession
  sufficient for participant impersonation.
- **One opaque combined keyring blob:** loses transactional session CAS and
  couples short-lived session renewal to signer replacement.
- **Automatic prompt or unlock:** violates non-interactive agent operation and
  lets the process trigger ambient UI.
- **Fallback to a file or in-memory key:** silently changes the custody boundary
  exactly when the selected provider is unavailable.
- **Caching the root key for the process lifetime:** enlarges exposure and makes
  relocking ineffective for subsequent operations.
- **Raw profile names in Secret Service attributes:** attributes are not secret
  and may disclose adopter structure.
- **Random-nonce AES-GCM without a lifecycle budget:** its smaller nonce space
  makes long-lived root-key safety depend on a tighter collision budget; this
  profile fixes XChaCha20-Poly1305 and still enforces a conservative use limit.
- **Claiming backup support without an anti-rollback anchor:** authenticated
  encryption detects modification, not replacement by an older valid snapshot.

## References

- [Freedesktop Secret Service API](https://specifications.freedesktop.org/secret-service/latest-single/)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869)
- [XChaCha and XChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
- [PKCS #8 / RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
