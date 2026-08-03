# RFC-0010: Identity and DPoP provider profile

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issues: #3 and #5
- Governing architecture: RFC-0002, RFC-0008 and RFC-0009

## Decision requested

Freeze the cryptographic, persistence, replay, revocation and recovery contract
for the identity provider selected by `single-node-v1`.

Acceptance authorizes three focused implementation increments:

1. strict JWT/JWKS and DPoP verification with independent fixtures;
2. the separate SQLite identity registry and recovery model;
3. composition behind RFC-0009 ports with a mandatory authentication-audit
   port and deterministic fake audit evidence.

Acceptance does not authorize a permissive audit implementation, policy
provider, administrative HTTP endpoint, process configuration, listener or
binary. The provider cannot make the future process ready until the real
security-audit provider and restore checkpoint gates are present.

## Security invariants

The provider preserves these invariants:

- an external principal is accepted only through one configured RFC 9068
  issuer and one exact relay audience;
- the external access token, its `cnf.jkt`, the DPoP proof key and `ath` all
  bind to one another;
- a relay token is an opaque 256-bit capability stored only as a
  domain-separated digest;
- a proof is accepted at most once across process restart for its complete
  validity window;
- one session binds exactly one tenant, principal, participant instance,
  epoch and DPoP thumbprint;
- inactive, expired, revoked, pending or indeterminate sessions never produce
  an admitted identity;
- every authentication allow or deny reaches the mandatory security-audit port
  before the HTTP edge receives a result;
- separate SQLite files are not described as one atomic transaction;
- restore cannot admit work until epoch non-reuse is proven against a durable
  checkpoint newer than or equal to the restored backup.

Loss of availability remains preferable to ambiguous identity or replay.

## Package and port boundaries

Implementation belongs under `internal/relay/identity`. It owns:

- external JWT validation and bounded JWKS refresh;
- strict DPoP proof validation;
- principal derivation;
- session-token generation and digesting;
- the separate SQLite identity database;
- proof replay reservation;
- session lifecycle and process-local revocation signals.

It implements `httpapi.SessionBootstrapper` and `httpapi.Authenticator` through
one composed provider. The HTTP package remains unaware of JWT, JOSE, keys,
SQLite and audit storage.

The provider depends on a narrow `AuthenticationAuditor` port. That port owns
durable authentication decision evidence in the separate security-audit
domain. No nil, no-op, in-memory or best-effort auditor is installed by a
production-capable constructor.

Administrative session revocation and restore fencing are separate internal
ports. They are not added to the public HTTP API and are not added to
`relay.Store`.

## Exact external JWT profile

Bootstrap accepts one compact signed JWT access token. JWE, detached content,
JSON serialization and nested JWTs are rejected.

The JOSE header contains exactly:

- exactly one signature;
- `typ` equal under ASCII case folding to `at+jwt` or
  `application/at+jwt`, then normalized to `at+jwt`;
- one `kid` string of 1 to 128 ASCII identifier characters;
- one configured asymmetric `alg` from `RS256`, `PS256`, `ES256` or `EdDSA`;
- no additional member.

The configured allow-list is exact, contains `RS256` as required by RFC 9068,
and may additionally contain only the other algorithms above. `none`, every
HMAC algorithm and algorithm/key-type mismatch are rejected before claims are
trusted. The provider never selects a key location from token content.

The claims set requires:

- exact configured `iss` string;
- `sub` as one non-empty string of at most 1,024 UTF-8 bytes;
- `aud` as either the exact configured audience string or a one-element array
  containing only that exact string;
- integer NumericDate `iat` and `exp` values;
- `jti` and `client_id` as non-empty strings of at most 256 bytes;
- `tenant_id` matching `^[a-z0-9][a-z0-9._:-]{0,255}$`;
- `cnf` containing exactly one `jkt` with a canonical 43-character base64url
  SHA-256 JWK thumbprint.

The first profile rejects `nbf` and unknown claims. An authorization server for
this audience must issue a minimal identity token rather than sending groups,
roles, profile data or unrelated entitlements to the relay. This minimizes
interpretation ambiguity and identity-domain personal data.

At validation time:

- `iat` may be at most 30 seconds in the future;
- the token may be at most five minutes old;
- `exp` must be later than the current time and later than `iat`;
- `exp - iat` may be no greater than 15 minutes;
- session expiry is the earlier of token `exp` and 15 minutes after bootstrap.

All string, object, member, depth and decoded-byte counts are bounded before
signature verification. Duplicate JSON member names at every depth, including
case variants of registered names, are rejected. Numeric claims accept only
lexical integers within the JSON-safe range; floating point, exponent notation
and lossy conversion are prohibited.

## Principal derivation and minimization

The stable `principal_id` is base64url-without-padding SHA-256 over:

```text
UTF8("yukh-coordination:principal:v1\n")
uint32be(len(issuer UTF-8 bytes))
issuer UTF-8 bytes
uint32be(len(subject UTF-8 bytes))
subject UTF-8 bytes
```

Length prefixes prevent concatenation ambiguity. The implementation publishes
exact derivation fixtures before acceptance.

Raw subject, access token, token `jti`, client ID and full claims are not stored
in the identity database. The database stores the derived principal, tenant
and the minimum session bindings. The authentication audit receives only
fields allowed by its closed record contract; it never receives token or proof
bytes.

## JWKS trust and refresh

Issuer, audience and JWKS HTTPS URL are three explicit configuration values.
There is no discovery request, issuer-derived URL or token-selected URL.

The JWKS client:

- uses a dedicated HTTP transport with no environment proxy;
- uses the configured TLS trust bundle and server name validation;
- follows no redirect;
- has explicit connect, TLS, response-header and whole-request deadlines;
- disables transparent compression;
- accepts only `application/json` or `application/jwk-set+json`;
- reads at most 256 KiB and 32 keys;
- rejects duplicate key IDs and keys without a unique non-empty `kid`;
- accepts only public signing keys matching configured algorithms and rejects
  private material or incompatible `use`/`key_ops` metadata.

The provider must fetch and validate one snapshot at startup. A snapshot has an
explicit soft refresh interval and hard maximum age from strict configuration;
the hard age cannot exceed five minutes. HTTP cache headers may shorten but
never extend those limits.

A known key may remain usable after a failed soft refresh only until the hard
age. An unknown `kid` triggers at most one single-flight refresh and is denied
if still unknown. Unknown-key refresh is rate-limited to at most once per 30
seconds so attacker-selected IDs cannot create an outbound request flood.
Expired or absent key state denies bootstrap and makes this provider unready.
No JWKS snapshot is persisted as unbounded trust across restart.

Refresh outcomes and key-set digest changes are security-audited without
recording key bodies or internal TLS details.

## Exact DPoP proof profile

Bootstrap and relay-session requests use the same strict proof verifier. The
compact JWS has exactly one signature and no detached payload.

The protected header contains exactly:

- `typ`: `dpop+jwt`;
- `alg`: `ES256`;
- `jwk`: a public EC JWK containing exactly `kty=EC`, `crv=P-256`, `x` and `y`.

Private parameters, `kid`, `jku`, `x5u`, certificates, unknown critical
headers and every additional member are rejected. The point must be on P-256
and the ES256 signature must verify before claims are used.

The claims object contains exactly:

- `jti`: 16 to 128 base64url characters;
- `htm`: exact uppercase method from RFC-0009 material;
- `htu`: exact normalized public URI from RFC-0009 material, with no query or
  fragment;
- `iat`: integer NumericDate;
- `ath`: base64url-without-padding SHA-256 of the exact ASCII credential.

Proof `iat` may be at most five seconds in the future and at most 60 seconds in
the past. `ath`, method, URI and JWK thumbprint comparisons use fixed-shape or
constant-time comparison where applicable. The JWK thumbprint is the RFC 7638
SHA-256 thumbprint and must equal:

- external JWT `cnf.jkt` during bootstrap;
- the persisted session thumbprint during resource authentication.

The profile does not issue a DPoP nonce in v1. Persistent one-use proof IDs and
the narrow time window provide the selected replay defense without adding an
uncontracted nonce challenge/retry exchange. Adding `DPoP-Nonce` requires an
HTTP contract revision and independent state analysis.

DPoP does not authenticate request bodies. Existing canonical event ID,
idempotency and transition rules continue to own append-body integrity.

## Cryptographic implementation boundary

The first implementation selects `github.com/go-jose/go-jose/v4` at exact
version `v4.1.4` for bounded JWS/JWT parsing, algorithm allow-lists, signature
verification, JWK validation and RFC 7638 thumbprints. Standard-library
`crypto`, `sha256`, `subtle`, `rand` and `base64` own primitive operations.

No generic “parse then inspect algorithm” convenience path is accepted. The
allowed algorithm is supplied to parsing/verification, headers and claims are
independently pre-scanned for duplicate names and bounds, and payload is never
used before signature verification.

Dependency acceptance requires exact module sums, vulnerability scanning and
negative fixtures for previously disclosed parser/panic classes. JWE code is
not exercised or exposed.

## Identity database profile

The identity adapter is a new SQLite database, not tables in the event Store.
It uses the same qualified driver family and operational baseline:

- WAL journal;
- `synchronous=FULL`;
- foreign keys enabled;
- five-second busy timeout;
- one connection and serialized writers;
- STRICT schema and explicit `user_version`;
- `BEGIN IMMEDIATE` for every state transition.

The initial logical schema contains:

### `identity_metadata`

Exactly one row containing profile/schema version, database ID, persisted wall
clock high-water and restore-fence state.

### `principal_epochs`

Primary key `(tenant_id, principal_id)` with the last committed positive
JSON-safe session epoch. Allocation increments this value in the same
transaction that creates a pending session. Exhaustion fails closed.

### `sessions`

One row per participant instance containing:

- tenant and derived principal;
- canonical UUIDv7 participant instance;
- positive session epoch;
- 32-byte domain-separated session-token digest;
- 32-byte DPoP JWK thumbprint;
- issued and expiry time as integer Unix milliseconds;
- state: `pending`, `active`, `revoked`, `expired` or `abandoned`;
- opaque bootstrap operation ID;
- activation audit receipt reference when active;
- bounded revocation time, reason and authority reference when revoked.

Unique constraints cover token digest, participant instance, and
`(tenant_id, principal_id, session_epoch)`. No raw token, proof, external
subject, JWT, JWK or claims blob is stored.

### `proof_replays`

Primary key `(jwk_thumbprint, proof_jti)` with proof purpose, `iat`, retention
deadline and optional participant instance. It contains no proof or credential
bytes. An index on retention deadline supports bounded cleanup.

### `restore_epoch_floors`

The most recent verified per-principal epoch floor supplied by a restore
checkpoint. Allocation uses the greater of the live counter and verified floor
before incrementing.

All stored identifiers and times have CHECK constraints matching provider
bounds. Updates are narrow state transitions with expected prior state; there
is no generic session update or delete API.

## Session token generation and lookup

The provider reads exactly 32 bytes from the operating-system CSPRNG and
encodes them as 43 base64url characters without padding. Collision handling is
bounded and security-audited; repeated CSPRNG or digest collision fails the
provider rather than silently weakening entropy.

The persisted digest is:

```text
SHA256(UTF8("yukh-coordination:session-token:v1\n") || ASCII(session_token))
```

Lookup uses the indexed 32-byte digest. Candidate comparison remains
constant-time before identity is returned. The plaintext token exists only in
provider memory until RFC-0009 serializes the one successful response; it is
never recoverable from the database.

## Bootstrap state machine across separate audit storage

Identity and security audit intentionally use separate SQLite files and
handles. WAL transactions across those files are not presented as atomic. The
provider instead uses an explicit fail-closed state machine:

1. verify external JWT and DPoP completely in memory;
2. generate participant ID and token;
3. in one identity transaction, check the clock fence, reserve the proof ID,
   allocate the epoch and commit a `pending` session;
4. append an idempotent `bootstrap_authorization` decision through the
   mandatory audit port, keyed by the bootstrap operation ID;
5. in a second identity transaction, bind the returned audit receipt and move
   the exact row from `pending` to `active`;
6. return the plaintext token to the HTTP edge.

No token is disclosed before step 5 commits. Audit failure leaves a pending,
unusable session and returns temporarily unavailable. Activation uncertainty
also returns temporarily unavailable and never creates a replacement for that
operation.

A crash before activation cannot create an admitted capability. On startup all
unexpired `pending` rows from a previous process incarnation become
`abandoned`; their epochs and proof reservations remain consumed. An audit
authorization record may exist for an operation that never activated, which is
truthful: it records the decision, not successful token delivery.

A crash after activation but before response can leave an active capability
whose plaintext token no client received. It expires normally and is safe but
unreachable. Bootstrap retry uses a fresh proof, participant instance, token
and epoch; it never recovers or replays the old secret.

This state machine provides explicit evidence and failure semantics without a
distributed-transaction claim.

## Resource authentication transaction

For an RFC-0009 session request the provider:

1. validates the DPoP structure, signature, method, URI, `ath` and time in
   memory and derives its thumbprint;
2. derives the opaque token digest;
3. begins one immediate identity transaction;
4. checks the persisted clock fence;
5. looks up exactly one active, unexpired session by token digest;
6. compares tenant-independent token digest and bound thumbprint;
7. inserts `(thumbprint, proof_jti)` into `proof_replays`;
8. commits before constructing `Identity`;
9. records the closed authentication allow through the audit port;
10. returns identity only after audit success.

The replay insert and session check are one transaction. Concurrent use of the
same proof yields at most one commit. If audit fails after replay reservation,
the request is not admitted and that proof remains consumed; the client must
retry with a fresh proof.

Invalid authentication decisions are also audited with a closed reason code.
If mandatory denial audit is unavailable, the provider returns temporarily
unavailable rather than silently dropping evidence. Public responses remain
the non-oracular RFC-0009 shape.

## Clock and replay retention

Every identity write observes UTC wall time through an injected clock and
compares it with the database high-water. A rollback greater than five seconds
makes the provider unready and denies bootstrap/authentication until an
accountable recovery operation supplies a valid fence. Small backward
adjustments do not extend the stored expiry or replay deadline.

A proof replay row is retained until strictly after the latest instant at which
its `iat` could pass the 60-second past window. Cleanup is bounded per
transaction and never deletes a row whose proof could still validate. Session
rows are retained beyond token expiry according to the future identity
retention policy; expiry changes admission immediately even before lazy state
materialization.

## Revocation and live streams

The internal administrative port exposes only expected-state operations:

- revoke one exact `(tenant, participant_instance_id, session_epoch)` with a
  closed reason and authority receipt;
- query exact active status;
- subscribe to the inactive signal for one already-authenticated identity.

Revocation commits before an in-process signal is closed. Subscription is
race-free: it registers first, then rechecks durable state; a revoke before
registration is observed by the read, and a revoke after registration closes
the signal. Expiry uses the same signal path through one bounded scheduler, not
one unowned goroutine per request.

The later authorizer composes this session-inactive signal with policy
revocation in `Decision.Revoked`, closing existing SSE streams. A process crash
already terminates its streams; after restart every new admission rechecks the
durable session state.

There is no public revoke endpoint in this increment. Principal-wide and
tenant-wide incident blocks belong to the signed policy/administration design;
they are not inferred from protocol events.

## Restore fencing and epoch non-reuse

An SQLite backup alone cannot prove that no higher session epoch committed
after that backup was taken. Restoring it without an external high-water could
therefore reuse an old `(principal, epoch)` and violate the threat model.

Every qualified identity backup is paired with an externally durable, signed
checkpoint containing database ID, backup identity/digest, checkpoint time and
per-principal epoch high-waters. The checkpoint contains derived principal IDs,
not raw subjects.

After restore the provider starts fenced and refuses bootstrap and resource
authentication. An accountable recovery operation verifies the checkpoint,
loads floors monotonically, records a restore audit receipt and changes the
fence to admitted. A checkpoint older than the restored backup, a missing
principal floor, database-ID mismatch, clock rollback or unverifiable
signature fails closed.

The identity implementation may build and test checkpoint import/export ports,
but no executable profile may claim restore readiness until the audit signer,
backup procedure and end-to-end restore qualification are merged. There is no
`--ignore-restore-fence` or fresh-epoch escape hatch.

## Authentication audit contract

Each audit call has a provider-generated UUIDv7 operation ID and a closed
record containing only applicable fields:

- profile/schema version and decision time;
- operation kind: bootstrap, session authentication, revocation, JWKS refresh
  or restore fence;
- allow, deny or unavailable outcome and closed reason code;
- tenant, derived principal, participant instance and epoch when already
  trusted;
- DPoP thumbprint digest when verified;
- activation or authority reference when applicable.

It excludes access/session tokens, proofs, JWT/JWK bytes, external subject,
token/proof `jti`, arbitrary provider errors and HTTP bodies. Calls are
idempotent on operation ID and return a durable receipt reference.

The real audit store, hash chain and exported checkpoint signature remain the
next security-domain increment. Identity-provider tests use an explicit fake
that records exact calls and injected failures; that fake is not available from
future process composition.

## Error and readiness posture

The provider returns only RFC-0009 error classes:

- malformed, invalid, expired, replayed, unknown-token, wrong-key and revoked
  authentication return `ErrUnauthenticated` after mandatory deny audit;
- JWKS hard expiry, database uncertainty, clock fence, audit failure and
  internal invariant failure return `ErrAuthenticationUnavailable`.

No parser, SQLite, HTTP, TLS, key, claim or audit error text crosses the port.
Secret-bearing inputs are never formatted into wrapped errors.

Provider readiness requires a valid current JWKS snapshot, open and unfenced
identity database, acceptable wall clock, functioning mandatory auditor and no
unresolved commit-indeterminate state. Readiness is diagnostic state, not an
authentication bypass.

## Qualification evidence

### JWT and JWKS

- exact positive vectors for every configured external algorithm;
- wrong/missing/case-variant `typ`, issuer, audience, tenant and required claim;
- ID token, JWE, multi-signature, HMAC, `none` and algorithm-confusion negatives;
- duplicate/case-collision keys, numeric edge cases and parser resource bounds;
- wrong key use/type/ops, duplicate/unknown `kid` and rotation;
- redirect, proxy, TLS, content type, compression, size, timeout, stale-cache
  and refresh-flood negatives.

### DPoP

- official or independently produced ES256/JWK-thumbprint vectors;
- wrong `typ`, algorithm, curve, private JWK member, signature and point;
- wrong `htm`, `htu`, `ath`, `cnf.jkt`, session thumbprint and time;
- duplicate claims/header members, query/fragment and Unicode/escape variants;
- same proof sequentially, concurrently and after restart admits at most once;
- expiry-boundary and replay-cleanup tests with a deterministic clock.

### SQLite and lifecycle

- exact schema, constraints and migration rollback;
- pending/audit/activation crash at every boundary;
- commit uncertainty never discloses a token or replacement identity;
- concurrent bootstrap yields unique monotonic epochs;
- token/digest/participant collision handling;
- session expiry, exact revoke and race-free watcher behavior;
- database reopen, WAL recovery and bounded cleanup;
- raw-token/proof/subject absence from database, errors and logs;
- backup restore remains fenced until a valid epoch checkpoint is applied;
- stale/missing/wrong-database checkpoint and clock rollback negatives.

### Composition

- all RFC-0009 edge tests pass through the real cryptographic provider and
  identity database with a deterministic audit fake;
- audit allow/deny precedes every returned authentication result;
- audit outage consumes reserved proof but admits no request;
- no provider dependency or test bypass is reachable from runtime defaults;
- race detector, fuzz targets for JOSE pre-scan, dependency vulnerability scan
  and abrupt subprocess tests are green.

## Delivery sequence

Implementation remains split to preserve reviewability:

1. strict JOSE pre-scan, external JWT/JWKS validator and DPoP verifier;
2. SQLite identity schema, session/replay transactions, revocation and restore
   fence ports;
3. composed RFC-0009 provider, mandatory audit port and end-to-end fixtures.

Each pull request records its session under `.context/sessions/` and updates
issue #5. No step adds `cmd/` or edits the event Store interface.

## Alternatives rejected

### Store sessions in the event database

Rejected because identity, transcript and their backup/retention authorities
are distinct failure domains in RFC-0008.

### Use a JWT as the relay session token

Rejected because immediate revocation and proof replay still require durable
state, while a self-describing token would expose identity and invite a second
claim-validation surface.

### Keep proof replay IDs only in memory

Rejected because restart would reopen the complete proof validity window.

### Use a SQLite transaction spanning identity and audit files

Rejected because the qualified profile uses separate WAL databases and cannot
honestly claim all-files atomicity. The explicit pending/audit/active state
machine preserves safe disclosure semantics instead.

### Activate before audit and compensate later

Rejected because compensation cannot retract a token already returned to a
client and would violate mandatory authentication audit.

### Put the session token in audit for recovery

Rejected because recoverable bearer capability material would turn the audit
domain into a credential store and enlarge compromise impact.

### Trust a restored identity database by itself

Rejected because a backup cannot contain epochs committed after its capture.
External epoch high-water evidence is required to prevent reuse.

### Require DPoP nonce immediately

Rejected for v1 because persistent `jti` replay protection and a narrow window
already close the selected replay boundary. Nonce introduces a new public
challenge/retry state machine and is revisited only with a contract RFC.

### Hand-roll JOSE verification

Rejected because parsing, algorithm selection, JWK validation and signature
edge cases are security-sensitive. A pinned maintained implementation plus
strict profile pre-scan is smaller and independently testable.

## Compatibility and rollback

The public RFC-0009 wire contract does not change. Provider configuration and
identity schema are new and have no compatibility promise before their
implementation review.

The JOSE verifier increment has no persistent state. Once the identity schema
is merged, migrations are forward-only and restore-tested. Rolling back code
must leave the process unready rather than open the database with an unknown
schema or fall back to bearer/test identity.

## Primary references

- [RFC 7515, JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7517, JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7519, JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7638, JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 9068, JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9449, OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9700, Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- [go-jose v4 documentation](https://pkg.go.dev/github.com/go-jose/go-jose/v4)
- [SQLite transactions across attached databases](https://www.sqlite.org/lang_attach.html)
