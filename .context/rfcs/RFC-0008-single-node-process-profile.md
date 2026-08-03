# RFC-0008: Single-node reference process profile

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issues: #3 and #5
- Governing architecture: RFC-0002, RFC-0003, RFC-0004, RFC-0005 and RFC-0007

## Decision requested

Freeze the first complete provider and operational profile that may eventually
turn the qualified relay runtime into an honest executable process.

The first process profile is deliberately single-node. It uses the qualified
SQLite Store and process-local live notifications. JetStream remains a
qualified distributed Store adapter, but it is not selectable by this process
profile until identity, policy, audit, revocation and retention also have a
distributed design.

Acceptance authorizes the focused provider and lifecycle increments listed in
this RFC. It does not by itself authorize a binary, deployment or
production-readiness claim. `cmd/` remains forbidden until every mandatory gate
in this RFC is implemented and qualified.

## Why a profile is required

The runtime now has mandatory ports for authentication, authorization and
signing, but no real providers. More importantly, the accepted threat model
also requires relay-issued session identity, immediate revocation, finite
retention, administrative provisioning and a separate security audit trail.

Adding a token parser and a key file would therefore not produce a valid
relay. The executable profile must close the entire security and operations
boundary rather than make the HTTP server merely start.

## Profile identity

The profile identifier is:

```text
yukh-coordination/single-node-v1
```

It targets one Linux process and one active instance. High availability,
multi-node session state and automatic failover are excluded. A supervisor may
restart the process, but two active instances against the same SQLite files are
not a supported topology.

The profile has three separate SQLite databases with distinct paths, handles,
file permissions and backup policy:

1. event database: the existing relay Store and transcript lifecycle;
2. identity database: session capabilities, epochs, DPoP replay state and
   revocation;
3. security-audit database: authorization, administration, key and incident
   records.

Separate files are logical failure-domain separation, not hardened tenancy.
The receipt private key is not present in any of them or in the relay process.

## External principal bootstrap

Exactly one configured OAuth authorization server is supported. Session
bootstrap accepts only JWT access tokens conforming to RFC 9068; ID tokens,
opaque external tokens, multiple issuers and token introspection are excluded
from this profile.

Validation is fail closed and requires:

- exact configured HTTPS issuer;
- exact configured audience dedicated to this relay;
- signature algorithm from a closed asymmetric allow-list;
- a configured JWKS source, with redirects disabled;
- valid `iss`, `sub`, `aud`, `exp`, `iat`, `jti` and `client_id` claims;
- explicit maximum token age and clock skew;
- one non-empty string `tenant_id` claim;
- no identity or tenant values from request headers or event bodies.

The implementation never follows `jku`, `x5u` or other token-selected key
locations. Unknown keys trigger at most one bounded refresh from the configured
JWKS source. Failure to validate a new token or refresh an expired key cache
denies bootstrap without falling back to stale unbounded trust.

The stable relay `principal_id` is a domain-separated base64url SHA-256 digest
of exact issuer and subject bytes. Raw external subjects are restricted to the
identity and security-audit domains and do not enter protocol events or NATS
subjects.

## Relay-issued sessions and DPoP

The profile adds one public bootstrap route under a focused revision of the
HTTP binding:

```text
POST /coordination/v1/sessions
```

The request has no body. It presents the external RFC 9068 access token and an
RFC 9449 DPoP proof carrying a client-generated ES256 public JWK. The proof
binds the exact method and public target URI. The access token and proof are
validated together on the same TLS request; bootstrap does not add a
profile-specific claim to the standard proof.

After successful external authentication the relay atomically:

1. allocates the next monotonically increasing session epoch for
   `(tenant_id, principal_id)` in the identity database;
2. creates a UUIDv7 `participant_instance_id`;
3. generates a 256-bit opaque session token from the operating-system CSPRNG;
4. stores only its domain-separated SHA-256 digest;
5. binds the session to tenant, principal, participant instance, epoch, DPoP
   JWK thumbprint, issue time and expiry;
6. records the bootstrap in the security audit database before returning.

The response is `Cache-Control: no-store`, contains the opaque token exactly
once and reports participant instance, session epoch and expiry. A session has
an explicit maximum lifetime no greater than 15 minutes. There is no refresh,
resume or transfer in v1; reconnection creates a new instance and epoch.

Subsequent append, replay and stream requests use the `DPoP` authorization
scheme and a fresh RFC 9449 proof. The proof must bind method, normalized public
URI, session-token hash, issued-at time, unique `jti` and the session public key.
Used proof IDs are retained in the identity database for the complete replay
window. Missing, repeated, expired or mismatched proofs are denied.

This changes the authenticator input from a bare token string to closed request
authentication material. The HTTP edge, not proxies or providers, constructs
that material after strict route and framing checks.

Session expiry or explicit revocation closes every authorization revocation
signal for that participant instance so existing SSE streams stop immediately.
The opaque token and DPoP proof are never logged or stored in plaintext.

## Signed policy and channel manifest

Channel administration is offline and declarative in the first profile. There
is no public administrative API.

The process consumes one closed JCS canonical policy manifest plus a detached
RFC 8032 Ed25519 signature. The verification public key and manifest path are
explicit non-secret configuration. The manifest contains:

- profile and schema version;
- tenant ID and monotonically increasing policy version;
- issue and activation time;
- exact immutable canonical channel metadata;
- finite retention policy documents and their digests;
- principal-to-channel action grants for `publish`, `replay` and `watch`;
- accountable tenant/channel administrator identity;
- export, redaction and deletion authority;
- manifest signing key ID.

No embedded policy language, executable expression, wildcard tenant or
network-loaded include is allowed. Closed data is preferable to introducing an
OPA, Cedar or product-specific policy engine before its semantics are needed.

At startup the provider verifies canonical bytes, detached signature, version,
activation, all digests and every cross-reference before reconciling channel
registrations through the Store. Any mismatch fails startup.

Reload is an explicit bounded polling operation over an atomically replaced
file. Only a correctly signed higher version can replace the active snapshot.
Unreadable, malformed or rollback content moves authorization to fail-closed
mode and closes all live revocation signals; the last policy is not silently
trusted forever. A new valid higher version may recover the provider and is
security-audited.

## Authorization and decision receipts

Authorization evaluates the immutable authenticated identity and active
manifest against exact `(tenant, channel, principal, action)` keys. It has no
network dependency and no allow default.

Every allow or deny is appended to the separate security-audit database before
the decision is returned. The canonical decision entry includes policy
version/digest, request identity and action, decision, time, reason code and a
UUIDv7 decision receipt ID. Allowed requests receive a canonical binding and
receipt reference from that durable entry.

Audit entries form a domain-separated SHA-256 chain within one audit epoch.
Updates and deletes are denied by schema triggers. This is tamper-evident
logical evidence, not protection against a host administrator who controls the
database and process. Exported audit checkpoints are signed through the
external receipt signer before the profile can make an operational integrity
claim.

## Receipt signing with Vault Transit

HashiCorp Vault Transit is the first receipt-signing provider. The profile uses
one non-derived, non-exportable Ed25519 key. The relay has only read-key and sign
permissions for the configured path; it cannot create, rotate, export, delete
or change key policy.

`Select` reads bounded key metadata, verifies type and signing capability, and
freezes the exact public key ID and Vault key version before Store admission.
`Sign` sends the exact persisted canonical preimage as base64 input with
`prehashed=false` and the selected `key_version`. It rejects a response with a
different version, malformed prefix or non-64-byte signature and locally
verifies the Ed25519 signature against the selected public key before durable
attachment.

The public receipt key ID is a configured stable alias plus Vault version; it
does not expose Vault address, mount or internal key name. Public verification
material and activation/retirement/compromise intervals require a separately
versioned signed key-set document.

Vault is reached only through HTTPS with a configured trust bundle. The relay
credential is delivered by a Vault Agent token sink file with restrictive
permissions and is re-read so rotation does not require process restart. Token
values never appear in process arguments, environment, logs, receipts or
configuration.

Vault unavailability before Store commit fails the signing selection and
accepts nothing. Unavailability after commit leaves the exact receipt pending,
as already governed by RFC-0002 and the append service.

## Retention, redaction and deletion gate

No executable may accept its first event until the SQLite adapter implements a
separate administrative transcript-lifecycle port governed by a focused RFC.
That RFC must freeze:

- retention expiry and scheduling;
- append-only redaction/deletion markers and signed administrative receipts;
- payload removal while retaining the permitted integrity minimum;
- transcript epoch rollover and identifier non-reuse;
- replay completeness and lifecycle reporting;
- export before destructive action when policy permits;
- event, identity and audit backup deletion windows;
- crash recovery and clock rollback behavior.

The lifecycle port is not added to `relay.Store`: ordinary append/replay code
must not acquire administrative deletion authority. The provider profile wires
it only to the signed manifest and an accountable administrative worker.

Until this gate is accepted and qualified, the future process may run
readiness diagnostics but must refuse event admission.

## Configuration and secret delivery

The future executable accepts exactly one non-secret `--config` path. The file
is strict closed JSON with an explicit profile version; unknown fields,
duplicate keys, unsafe permissions and relative paths fail startup. There are
no operational defaults.

Configuration contains paths and public identifiers, never bearer tokens,
private keys or inline credentials. Secret material is referenced through
files with restrictive deployment ownership and permissions, specifically the
TLS private key and Vault Agent token sink. They must be readable by the relay
account and not writable by that account or by unrelated users. Environment
variables and command-line flags do not carry secrets or override individual
fields.

The process validates that event, identity and audit database paths are
distinct regular files under explicitly configured directories. It refuses
symlinks, shared paths, memory databases and network filesystems in the
qualified profile.

## Network and operational surfaces

The public listener terminates TLS directly in the Go process. TLS forwarding
headers are ignored. Certificate/key paths, minimum TLS version and public base
URI are explicit; public URI normalization for DPoP uses that configured base,
never untrusted Host or forwarded headers.

A second operations listener is mandatory and must bind an explicit loopback
address. It exposes only:

- `/livez`: process event loop is alive;
- `/readyz`: all mandatory provider gates currently admit work;
- `/metrics`: bounded low-cardinality process and security counters.

It exposes no tenant, principal, channel, event, receipt, policy body, token,
path or Vault identifier labels. Profiling, configuration, administration and
debug endpoints are disabled. A non-loopback operations bind fails startup.

Structured process logs go to stderr as bounded JSON and exclude request
bodies, tokens, proofs, authorization bindings and provider response bodies.
The security audit database, not stderr, owns sensitive decision evidence.

## Binary authorization gate

Only after every item below is merged and green may a final review authorize
the `cmd/yukh-coordination-relay` composition and add `cmd/` to the repository
map:

1. request-aware authentication input and session bootstrap binding;
2. RFC 9068 validator and persistent DPoP-bound session registry;
3. signed manifest, channel reconciliation, authorization and revocation;
4. separate hash-chained security audit store and restore evidence;
5. Vault Transit signer and public verification key set;
6. accepted and implemented transcript-lifecycle RFC;
7. strict configuration loader and direct TLS listener;
8. isolated operational listener, bounded metrics and structured logs;
9. end-to-end restart, outage, revocation, retention and negative isolation
   qualification;
10. exact dependency and container-image pins with an SBOM and provenance.

The final binary review is evidence-based. Acceptance of this RFC alone does
not waive any item.

## Delivery sequence

Implementation proceeds in focused, separately reviewed increments:

1. HTTP authentication-material and session-bootstrap contract;
2. identity database and DPoP session provider;
3. signed policy manifest, authorization and audit;
4. Vault Transit signer;
5. transcript lifecycle design and implementation;
6. configuration and operations surfaces;
7. executable composition and full qualification.

Each increment remains in this repository because it implements a
Yukh Coordination relay boundary. Vault deployment, authorization-server
deployment and client DPoP key custody remain external responsibilities.

## JetStream and Matrix boundaries

JetStream remains implemented and qualified as a Store plus wake-up adapter.
It is not removed or deprecated. A later distributed process profile must
select distributed session, policy, audit and lifecycle stores and prove their
cross-component failure semantics; it cannot silently reuse the single-node
SQLite provider state.

Matrix remains a client bridge over the public contract. It does not supply
identity, ACL policy, receipt signing, retention or process health to the relay.

## Qualification evidence

The profile requires, at minimum:

- JWT wrong issuer/audience/algorithm/key/tenant and stale-JWKS failures;
- DPoP wrong method/URI/key/token hash, replay and clock failures;
- session restart, expiry, revocation and monotonically increasing epoch;
- policy signature, rollback, corruption, reload and cross-tenant negatives;
- durable allow/deny audit before response and hash-chain restore checks;
- Vault wrong key type/version/signature, outage and rotation recovery;
- channel provisioning conflict and finite-retention enforcement;
- redaction/deletion crash and backup-restore behavior;
- direct-TLS and hostile Host/forwarded-header tests;
- non-loopback operations-listener rejection and metrics cardinality checks;
- secret scanning of logs, errors, process arguments and configuration;
- abrupt restart at every append/sign/audit/lifecycle boundary;
- one full two-session protocol flow through the real process.

## Alternatives rejected

### Enable the JetStream process first

Rejected because a distributed event log with single-process identity,
authorization, audit or retention would create inconsistent security state and
misrepresent the adapter as a complete distributed relay.

### Long-lived bearer tokens without proof of possession

Rejected because stolen bearer material is replayable. Short-lived opaque
relay sessions bound to DPoP reduce that risk and give the relay explicit
participant-instance lifecycle.

### Use OIDC ID tokens directly on every relay request

Rejected because ID tokens are for the client and do not create relay-issued
participant identity, session epochs, immediate relay revocation or
audience-scoped proof for each resource request.

### Store the Ed25519 private key beside SQLite

Rejected because it places transcript and receipt attribution in the same host
storage failure domain and prevents independent key version selection.

### Add OPA or Cedar now

Rejected because the MVP needs exact membership/action grants, not a general
policy language. A signed closed manifest is smaller, deterministic and easier
to audit.

### Put audit records in the protocol transcript

Rejected because RFC-0002 states that the coordination transcript is not the
complete security audit log and denied requests cannot be written into a
channel they were not authorized to discover.

### Ship an insecure development mode

Rejected. No allow-all policy, universal token, local event-database key,
plaintext HTTP or retention bypass is compiled into the executable profile.

## Compatibility

Existing append/replay/stream payloads, receipts, Store commands and cursors do
not change. The session bootstrap route and DPoP authentication scheme are an
additive public edge revision requiring focused fixtures before implementation.

The profile introduces no compatibility promise for external configuration
until the final binary review freezes its schema.

## Rollback

Provider increments can be removed before binary authorization without event
data migration. Once identity or audit schemas are accepted, their migrations
must be forward-only and restore-tested. A failed provider rollout leaves the
process unready and event admission closed; it never falls back to test
providers or unsigned policy.

## Primary references

- [RFC 9068, JWT Profile for OAuth 2.0 Access
  Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9449, OAuth 2.0 Demonstrating Proof of
  Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9700, Best Current Practice for OAuth 2.0
  Security](https://www.rfc-editor.org/rfc/rfc9700)
- [RFC 8785, JSON Canonicalization
  Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 8032, Edwards-Curve Digital Signature
  Algorithm](https://www.rfc-editor.org/rfc/rfc8032)
- [HashiCorp Vault Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [HashiCorp Vault Transit HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
