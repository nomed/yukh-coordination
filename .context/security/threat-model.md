# Yukh Coordination MVP threat model

- Status: Draft
- Governing issue: #3
- Last updated: 2026-08-02

## Decision requested

Freeze the minimum identity, admission, isolation, privacy, retention, receipt, persistence, and incident boundary required before a reference relay is designed.

This document does not authorize a production identity provider or relay implementation.

## Security boundary

The relay accepts, validates, attributes, stores, and replays coordination statements. It does not grant execution capability, decide project ownership, validate reviewer independence, or hold adopter execution credentials.

Loss of availability is preferable to ambiguous admission or acknowledgement.

## Assets

- channel membership and access policy;
- authenticated principal and participant bindings;
- tenant/channel isolation;
- immutable event bytes and transcript integrity;
- append sequence and idempotency records;
- claim and handoff history;
- evidence metadata and digests;
- retention, redaction, export, and deletion policy;
- receipt signing keys and security audit records;
- service availability and recovery state.

## Actors

- human principal;
- agent or session participant instance directly bound to its one authenticated principal;
- accountable tenant administrator, who owns tenant policy and appoints channel administrators;
- accountable channel administrator, who owns membership, retention, export, redaction, and deletion decisions for one channel;
- security owner, who owns threat treatment, incident declaration, and residual-risk acceptance;
- relay operator, who operates availability and recovery but cannot silently grant channel access;
- relay security administrator, who manages authenticators and receipt keys under separated access;
- external authority or governance system;
- evidence host and independent evidence verifier, whose verification is a statement rather than relay authority;
- unauthenticated attacker;
- malicious or compromised admitted participant;
- compromised relay or operator.

## Trust zones

1. **Client runtime:** untrusted event construction and local agent execution.
2. **Authenticated transport:** TLS termination and authenticator boundary.
3. **Relay validation/admission:** identity binding, authorization, schema and quota enforcement.
4. **Tenant-scoped event store:** atomic event, sequence, idempotency, and receipt state.
5. **Administrative control plane:** tenant/channel creation, membership, retention and incident actions.
6. **External evidence/authority systems:** untrusted until independently verified.

## MVP security decisions

### Identity

The system distinguishes:

- `principal_id`: stable authenticated subject, derived by the relay;
- `participant_instance_id`: relay-issued identifier for exactly one person/session/agent instance bound directly to exactly one authenticated principal;
- `session_epoch`: relay-issued monotonically distinct epoch that prevents reconnection or restored client state from reusing a prior instance binding;
- `display`: mutable, non-unique advisory text.

During authenticated session bootstrap, `participant_instance_id` and `session_epoch` are issued and returned by the relay and bound directly and exclusively to one authenticated `principal_id`, tenant, authentication context, and creation time. They cannot be selected, reused, transferred, or rebound by a client. Reauthentication or reconnection creates a new instance/epoch unless the relay validates a narrowly scoped, integrity-protected resume capability. A restored client cannot resurrect an earlier epoch.

Client assertions MUST NOT establish authenticated identity. Participant identity carried by an event is an advisory label. Only the receipt binds the authenticated principal, relay-issued participant instance, and session epoch. Delegation is excluded from the MVP: a participant cannot act for or be attributed to another principal. Session lineage, kind, and display are advisory and non-authorizing. Delegation, workload identity, and delegated agent credentials require a future RFC.

The reference MVP supports TLS plus one configured authenticator behind a provider-neutral interface. Identity from event bodies, forwarded headers, display names, or presence is rejected for authorization.

### Admission and channel administration

Admission is deny-by-default and separate from work authority. Channel creation and membership are administrative policy outside the protocol event log.

Every channel has one immutable registered canonical URI mapped to its internal channel ID and tenant. Registration rejects an existing URI mapped to a different identity; aliases and URI reassignment are excluded from the MVP. Work and channel URIs are canonicalized only by a frozen protocol rule, never by network dereference.

Every create, publish, read, watch, replay, export, redact, and delete action is authorized against `(tenant, channel, principal, action)` before existence is disclosed or state changes. The accountable tenant or channel administrator changes a versioned ACL through the administrative control plane. Each decision produces an immutable ACL decision receipt containing policy version/digest, principal, action, resource, decision, decision time, and administrator/decision-engine identity. Claim, presence, review, verdict, and handoff events never alter ACLs.

### Tenant and channel isolation

Tenant identity is relay-derived. Channels use immutable internal IDs bound to exactly one tenant. Storage and index keys begin with tenant ID; every query includes tenant and channel predicates. External names and cross-channel references cannot bypass scope.

Denied access MUST NOT reveal whether a tenant, channel, event, participant, cursor, or evidence reference exists.

Public denial precedence is fixed: enforce transport/framing limits and coarse abuse controls; authenticate; authorize tenant/channel without disclosing existence; only then perform protocol/schema and transition validation. Authentication failure uses one common unauthenticated response. Missing and unauthorized state after authentication use one common non-enumerating admission response; validation detail is available only inside an admitted scope.

The accountable isolation owner is the relay security administrator; the tenant administrator accepts tenant-specific residual risk. Authentication, admission policy, relay compute, event persistence, security audit, receipt signing, backup, and evidence verification are named failure domains. The signing key MUST be outside the event-database failure domain; evidence verification MUST be outside relay admission and write transactions. Shared compute or storage is logical isolation only and cannot be described as hardened production tenancy until negative cross-tenant tests, restore tests, credential separation, operator-access review, resource-exhaustion tests, and compromise/blast-radius evidence pass for the exact deployment topology.

### Validation, append, and replay

The relay enforces closed schemas, version allow-lists, canonical lexical formats, safe Unicode, and frozen size/count/depth/string limits before persistence.

The relay assigns receive time and a monotonically increasing sequence within one tenant/channel log. Client time and IDs do not establish order, expiry, ownership, or authorization.

Canonical event bytes, authenticated identity and ACL bindings, transcript epoch, sequence assignment, idempotency record, event digest, append outcome, receipt ID, and complete immutable canonical unsigned receipt preimage commit atomically. No success receipt is returned before commit and durable signature attachment. Exact duplicate bytes are idempotent; same ID with different bytes is rejected and security-audited.

The normative receipt preimage is a canonical, domain-separated object containing protocol and receipt versions, tenant ID, internal channel ID, registered canonical channel URI, transcript epoch, server sequence, event ID, canonical event digest, authenticated principal ID, participant instance ID, session epoch, ACL policy version/digest and decision-receipt reference, receive time, append outcome, receipt ID, selected signing key ID, and selected signature algorithm. Canonical byte serialization, signature input, and verification outcomes require byte-exact fixtures before implementation acceptance. The persisted preimage is never reconstructed from mutable policy or current key configuration.

The selected key must be eligible and available before the transaction begins; the signer remains outside the database. The complete unsigned receipt preimage and append outcome are committed atomically with event state before signing or acknowledgement. A crash before commit yields no accepted event. A crash after commit but before signing or acknowledgement may lose the response; retry of the same event ID and exact canonical bytes addresses the same preimage and returns the same committed outcome and receipt identity once the signature is durably attached, while changed bytes conflict. If commit state cannot be proven after recovery, the relay fails closed and reports an indeterminate non-success response; it never creates a replacement event or advances ownership from ambiguity.

Replay cursors are tenant/channel scoped and opaque or integrity-protected. Page size, replay window, connection count, and processing time are bounded.

### Impersonation and handoff

Display collisions are allowed but visibly disambiguated by principal and participant bindings. Reconnect cannot silently reuse an old participant identity.

Claims bind canonical channel URI, canonical work URI, claimant principal, participant instance/session epoch, and a claim generation. In the MVP the handoff recipient is exactly one `participant_instance_id`; principal-wide or delegated recipients are invalid. Handoff acceptance must be emitted by that exact authenticated participant instance/session epoch and bind the source claim generation, channel, work identity, boundary digest, and evidence-set digest. Release, supersession, changed boundary, late acceptance, wrong session epoch, or competing acceptance yields a deterministic diagnostic and no observable transfer. Handoff changes protocol-observable claim state only; external authority remains external.

### Evidence and SSRF

The core relay stores evidence URI, media type, digest/revision, declared size, and advisory description. It MUST NOT fetch arbitrary evidence URIs.

Verification occurs under a separate client/verifier policy. Digest mismatch, unavailable content, unauthorized retrieval, mutable content, and unknown algorithms remain explicitly unverified. A digest proves bytes, not truth or authorization.

`evidence_verification` is a separately authenticated durable statement. Its receipt binds the authenticated verifier principal/instance/epoch; its payload binds evidence URI, algorithm, expected digest, observed digest or reason, verification time, verifier policy/version, and result (`verified`, `mismatch`, `unavailable`, `unauthorized`, or `inconclusive`). It never rewrites the original evidence entry or automatically changes a claim, handoff, review, or verdict.

Credential-bearing URLs, inline evidence bodies, private prompts, unrestricted logs, and secrets are prohibited.

### Privacy, retention, and redaction

Channels are private by default and have no public directory. Event bodies prohibit credentials, secrets, private prompts, unrestricted logs, and personal or special-category data. Operational logs redact authorization material and exclude bodies by default.

The caller and its accountable data owner are responsible for classifying content before submission and for applying organization-specific secret, privacy, legal, and residency policy. Relay validation and prohibited-field detection are defense in depth, not a claim that arbitrary text is free of secrets or personal data. A caller MUST omit or minimize prohibited data; rejection does not transfer data-controller responsibility to the relay. Evidence verifiers likewise apply caller-approved retrieval, credential, egress, and disclosure policy outside the relay.

A finite channel retention policy MUST be explicitly configured and decision-receipted before accepting its first event. There is no implicit or inherited default. The policy freezes active retention, backup deletion window, permitted export, redaction/deletion authority, and minimal integrity metadata retained after payload removal.

Each new channel history starts a monotonically distinct `transcript_epoch`. Export and replay report two independent dimensions: completeness (`complete` or `incomplete`, with missing sequence boundaries/reason) and lifecycle (`active`, `redacted` with marker references, or `deleted` with the surviving deletion receipt permitted by policy). Epochs cannot be joined silently, missing data cannot mean “never accepted,” and deleted identifiers cannot be reused to manufacture continuity. An incomplete or non-active transcript cannot assert a final claim/handoff/work projection. Accepted payloads are not silently edited.

The MVP supports:

- immediate access revocation;
- whole-transcript export;
- explicitly audited destructive transcript deletion;
- selective redaction only through an append-only marker plus payload removal/restriction, preserving minimal integrity metadata.

Backups and replicas publish a bounded deletion window. The project MUST NOT promise both permanent full payloads and erasure. Retention expiry, selective redaction, whole-transcript deletion, epoch rollover, and recovery after backup restore each produce deterministic administrative/audit evidence.

### Receipts and signing

Client signatures are excluded from the MVP unless offline/federated verification is promoted later.

Authenticated transport and relay-attributed durable receipts are required. Receipts use the canonical preimage defined above and are signed with a relay-owned asymmetric key stored and operated outside the event database and its backup/restore failure domain. Key ID, algorithm, public verification material, activation/retirement overlap, revocation, compromise interval, maximum ACK retry horizon, and recovery window are documented. The selected private key remains available for a declared recovery window at least as long as the maximum retry horizon. Rotation selects a new key only for new appends and never rewrites committed preimages.

Signing may occur after commit, but no success ACK is returned until the signature is durably attached to the preimage/receipt ID. Temporary signing failure leaves the append committed and exact byte-identical retries pending against the same preimage. Permanent loss of the selected key before signing leaves the event committed with no success ACK; re-keying and replacement are prohibited, a deterministic permanent-signing-failure plus incident evidence is recorded, and replay/export marks the boundary incomplete.

A normally retired key remains valid for receipts in its declared validity window. Compromise revocation publishes an affected interval: signatures in that interval can be cryptographically verified but their trust result is `indeterminate`. Other revocation reasons and results are policy-defined and versioned.

A database-local HMAC or a key in the same compromise domain is insufficient for independent verification.

### Denial of service and abuse

The implementation enforces per-principal, tenant, and channel quotas; event/evidence size limits; bounded depth and string length; replay/window limits; connection and concurrency limits; timeouts; and backpressure.

Compressed payload expansion, log injection, high-cardinality telemetry, public URL fetching, and unbounded channel discovery are prohibited. Admission and administration use stricter limits than ordinary publication.

### Security audit

A restricted security audit log records authentication/authorization decisions, ACL and administrative changes, rejected writes, rate limiting, key lifecycle, export, redaction, deletion, and incident actions. It excludes credentials and event bodies by default and correlates to event/receipt IDs.

The protocol transcript is not the complete security audit log.

## STRIDE threat register

Severity and likelihood are `low`, `medium`, `high`, or `critical`; treatment is `mitigate`, `avoid`, `transfer`, or `accept`. The named security owner owns this register. Only the tenant administrator may accept tenant-specific residual risk; only project governance may accept protocol-wide residual risk.

| Threat | Severity | Likelihood | Treatment and owner | Residual risk / acceptor |
|---|---|---|---|---|
| B declares A's participant/display | high | high | mitigate: relay security administrator issues identity bindings | compromised authenticator; security owner and tenant administrator |
| Same event ID with changed bytes | high | medium | mitigate: relay operator implements canonical digest and atomic collision rejection | canonicalizer defect; project governance |
| Participant denies a handoff | high | medium | mitigate: relay security administrator owns signed attributed receipts | relay/key compromise window; security owner |
| Cross-tenant channel guessing | critical | medium | avoid/mitigate: isolation owner enforces authorize-before-lookup and scoped storage | shared-infrastructure/operator compromise; tenant administrator after qualification |
| Replay exhaustion or deep payload | high | high | mitigate: relay operator owns quotas, bounds, timeouts and backpressure | noisy-neighbor degradation; tenant administrator |
| Claim or handoff elevates ACL/authority | critical | medium | avoid: protocol events cannot alter ACL or external authority | faulty adapter interpretation; project governance |
| Evidence URI targets internal service | high | high | avoid: relay never fetches; evidence verifier owns separate egress policy | verifier compromise; verifier owner/tenant administrator |
| Duplicate/late handoff acceptance | high | medium | mitigate: relay operator enforces idempotency, generation and epoch preconditions | external authority race; tenant administrator |
| Operator manipulates transcript/key | critical | medium | mitigate: security owner separates admin/signing access, audit, and rotation | post-compromise attribution suspect; project governance |
| Permanent payload conflicts with erasure | high | medium | avoid/mitigate: channel administrator freezes finite retention and audited deletion | minimal metadata/backups within declared window; tenant administrator/data owner |

## Fail-closed conditions

No new durable acceptance is permitted when authentication, authorization, tenant resolution, schema validation, idempotency lookup, storage commit, sequence assignment, or pre-commit selected-key eligibility/availability is uncertain. After an atomic commit, signing uncertainty cannot erase or replace the append, but no success receipt is returned until its persisted preimage is signed.

Authentication or ACL provider timeout, signing-key unavailability, partial persistence, and ambiguous tenant/channel binding return non-enumerating temporary failures.

All denial and temporary-failure responses use the same externally observable status family and bounded timing posture for unknown and unauthorized tenant, channel, event, participant, cursor, evidence, or ACL state. Detailed causes are restricted to the security audit and MUST NOT create an existence oracle.

## Normative design requirements and future evidence

The identity bindings, immutable channel mapping, versioned ACL decision receipts, canonical signed receipt boundary, atomic crash/retry semantics, mandatory retention, transcript epoch states, isolation ownership, claim/handoff/evidence-verification bindings, non-enumerating errors, role accountability, and fail-closed rules above are normative design requirements for the MVP protocol boundary.

They are not evidence that a relay, authenticator, database, signer, verifier, backup system, or deployment currently satisfies them. Issue #3 may accept the documented boundary while implementation and qualification evidence remains assigned to its governing implementation/conformance issues. No production-readiness statement follows from accepting this Draft.

Before relay implementation can be accepted, executable evidence must cover:

- spoofed participant/display and forged forwarded identity;
- stolen, expired, revoked, or wrong-tenant credential;
- non-member read, publish, watch, and replay;
- cross-tenant channel/event/cursor guessing;
- exact duplicate and same-ID/different-byte collision;
- delayed and reordered client events;
- wrong-recipient, late, replayed, and competing handoff acceptance;
- evidence SSRF attempt, credential URL, digest mismatch, unavailable URI, and non-dereference by relay;
- secret/log injection, oversized/deep event, and replay exhaustion;
- authentication, ACL, signing, and storage outage;
- deletion/redaction request and compromised signing key.

The exact implementation candidate must additionally publish its logical/physical isolation topology, component and configuration identities, failure-domain map, limits, restore procedure, transcript epoch behavior, signer separation, and test results. Shared-component tenancy remains unqualified until the isolation evidence named above is independently reviewed.

## Incident response minimum

The runbook identifies an accountable owner and covers credential/session revocation, principal/channel suspension, signing-key compromise and rotation, tenant export/deletion, evidence-host compromise annotation, forensic preservation, notification, and recovery verification.

After relay compromise, transcript attribution after the last independently trusted checkpoint is treated as suspect.

## Deferred production gates

- multi-IdP lifecycle and SCIM;
- workload identity and delegated agent credentials;
- federation and offline ingestion;
- end-to-end encryption;
- HSM/KMS and formal key ceremonies;
- regional/data-residency controls;
- legal hold and DSAR automation;
- external transparency log;
- multi-region isolation and disaster recovery;
- advanced abuse detection and public channels;
- untrusted adapters and formal penetration test.

## Accepted private primitives staging profile — 2026-08-03

- Governing issue: #90
- Accepted architecture: RFC-0022
- Scope: one private-network, direct-TLS primitives process with registered
  short-lived DPoP workload identity, fixed authorization, JetStream KV,
  capability sealing, security audit and loopback operations

The accepted profile introduces a real but explicitly non-production network and
credential boundary. It does not reuse relay sessions and grants no authority
over MCP policy, approval, providers or protected targets.

| Threat | Accepted control | Residual risk / dependency |
|---|---|---|
| server or target substitution | private explicit trust root, direct TLS 1.3, exact public base URI, no forwarding-header authority | private root and supervisor compromise remain staging failure domains |
| stolen workload credential | short-lived random token bound to one ephemeral P-256 DPoP key; no bearer fallback | simultaneous token/key theft within the validity window can impersonate the workload |
| DPoP replay or URI confusion | strict proof profile, durable replay reservation, exact configured `htu`/`htm`, ignored Host/forwarded headers | replay database loss fails readiness and requires accountable recovery |
| authorization broadening | signed expiring closed registration and route-derived five-action allowlist | offline policy-key compromise can authorize the one staging service |
| secret or capability disclosure | inherited descriptors, bounded one-time reads, redacted wrappers, closed audit/log schemas | plaintext exists in process memory; this is not HSM-backed production custody |
| cross-tenant or storage confused deputy | authenticated tenant-derived store keys and least-privilege fixed KV configuration | JetStream/operator compromise remains outside consumer isolation |
| restore or stale fence reuse | exact positive restore epoch across service and buckets; mismatch denies readiness | recovery availability is lost until epoch evidence is restored |
| audit omission | mandatory RFC-0011-compatible append before decisions and fail-closed readiness | one-host audit is tamper-evident, not independently witnessed |
| timeout repeats an ambiguous mutation | one bounded request, no retry, explicit consumer reconciliation | availability loss can halt the qualification lifecycle |

RFC-0022 authorizes implementation and hermetic qualification only.
Infrastructure provisioning, credential minting, listener exposure, live
traffic, MCP connection, provider execution, mutation and production use remain
separately gated.

### RFC-0022 authentication-foundation implementation review — 2026-08-03

Issue #95 implements only the pre-listener security foundation. Configuration
is closed and bounded, accepts only an explicit HTTPS origin and private or
loopback literal binds, and validates absolute non-symlink-controlled paths.
Secret descriptors use a distinct supervisor-only, non-serializable API. The signed canonical
registration fixes one identity, five actions, token digest, DPoP thumbprint,
key identifier and a validity interval of at most fifteen minutes.

Request admission verifies strict ES256 DPoP headers and claims, exact POST
method and target URI, token hash binding, registration expiry and key
thumbprint before durably reserving `(thumbprint, jti)`. The SQLite replay store
uses a single-writer `BEGIN IMMEDIATE` transaction, WAL plus full synchronous
writes, a bounded entry count, durable clock high-water fencing and fail-closed
readiness. Concurrent and restart tests require exactly one admission for one
proof. Secret-bearing values expose only redacted string forms and reject JSON
marshalling.

This evidence does not qualify a network boundary: no listener, route parser,
TLS runtime, operations endpoint, JetStream adapter, capability key, audit
composition, deployment or MCP traffic exists in #95. Those controls require a
separate reviewed increment before any connection can be exercised.

### RFC-0022 listener implementation review — 2026-08-03

Issue #99 composes the existing RFC-0015 HTTP handler behind a direct TLS 1.3
runtime. The server certificate and private key must form one pair, the leaf
must verify to the explicit configured trust bundle for the exact public URI
host, file identity is rechecked across bounded reads to reject replacement or
symlink races, dynamic TLS callbacks and client-certificate identity are disabled, and
the listener addresses must equal the closed configuration. Request authority
continues to derive only from the configured public base URI: `Host`,
`Forwarded` and `X-Forwarded-*` values do not affect DPoP target binding.

The independent operations listener is constrained to the configured loopback
address and exposes only bounded `livez`, `readyz` and low-cardinality readiness
metrics. Readiness is the conjunction of explicit injected probes and is
removed before bounded shutdown; a failed probe also denies public requests
before authentication or replay reservation. Both servers use fixed header, read, write
and idle bounds. Hermetic tests generate a private root and workload material,
exercise a real TLS primitive request, reject TLS 1.2, test hostile forwarding
headers and prove readiness removal.

This increment does not claim deployable readiness. Mandatory audit,
capability-key custody and exact JetStream configuration/epoch probes are not
yet concretely composed; infrastructure, credential minting, listener exposure
and MCP traffic remain gated.

### RFC-0022 mandatory audit-gate implementation review — 2026-08-03

Issue #102 reuses the RFC-0011 canonical receipt, append-only chain, Merkle and
STRICT SQLite ledger. Its closed v1 record schema gains only the RFC-0022
staging authentication, authorization and lifecycle operations plus profile,
action and derived identity-reference fields. Legacy record shapes explicitly
reject those new fields, so they cannot be smuggled into an unrelated audit
operation.

The staging gate appends the registration-load event at construction, records
credential expiry with its own closed denial reason, latches append uncertainty
until restart and wraps
authentication plus action/scope authorization. Allow, deny and dependency
unavailable results are returned only after the corresponding append commits;
append uncertainty becomes temporary unavailability. Runtime TLS-ready,
startup, unready admission and shutdown events use the same gate, and ledger
verification participates in conjunctive readiness.

Identity references are domain-separated hashes. Records exclude token, proof,
JTI, JWK, capability, request/response body, tenant/principal plaintext,
scope/value/holder digest, endpoint, path, NATS details and arbitrary errors.
Hermetic tests inspect persisted canonical bytes, verify restart continuity and
prove append-failure denial.

Capability-key custody, JetStream/epoch composition, provisioning and MCP
traffic remain separate gates.

### RFC-0022 capability-key custody implementation review — 2026-08-03

Issue #104 consumes one canonical closed capability keyring exactly once from
the supervisor-provided descriptor. Configuration contains only the descriptor
contract and maximum lease lifetime, never key bytes. The keyring admits one
active key and at most one decrypt-only predecessor; duplicate identifiers,
future-only or overlapping seal windows, multiple active keys and expired or
over-retained material fail closed.

Each decrypt window ends exactly one configured maximum lease lifetime after
its seal window, bounding rotation retention while preserving every capability
sealed before the cutoff. The provider implements the existing neutral
`SealingKeyProvider`; unknown or expired key IDs remain non-enumerating
unavailability. Held material is best-effort memory-locked on Linux, excluded
from strings/JSON/errors, and deterministically cleared and unlocked at close.
Secret JSON fields and canonical parsing copies use clearable byte buffers
rather than immutable Go strings.

Key load and zeroization are committed through the mandatory staging audit
gate. The runtime now requires a ready secret-custody dependency and closes it
before appending `stopped`. Tests cover old-capability opening across rotation,
ambiguous windows, expiry, retention bounds, descriptor closure/reuse,
oversized or truncated input, audit failure, redaction and backing-buffer
zeroization.

JetStream/epoch composition, provisioning and MCP traffic remain separate
gates.

### RFC-0022 JetStream/epoch composition implementation review — 2026-08-03

Issue #108 composes only the accepted RFC-0012 nonce, fenced-lease and bounded
capability-accounting KV stores. The closed staging configuration fixes one
NATS server URI, connection and request timeouts, replicas, retention, replay
safety, capability bounds and the same positive restore epoch consumed by the
primitives service. Normal opening always disables bucket bootstrap and the
existing adapter revalidates every immutable bucket property and epoch.

The NATS credential is read once from the supervisor descriptor under a fixed
byte bound, the descriptor is closed immediately, and the held credential is
best-effort memory locked until the owned connection closes and the buffer is
cleared. The client disables reconnect and maps connection, authentication,
bucket and probe details to one redacted unavailable result. This increment
permits only a literal loopback `nats://` target; remote or TLS NATS requires a
later contract with an explicit NATS trust bundle and is not silently delegated
to system roots.

Storage epoch validation commits through the mandatory staging audit gate.
Readiness requires the live connection and fresh exact probes for the nonce,
lease and budget buckets. Runtime shutdown removes readiness, closes the
dependency set in reverse order, closes NATS ownership, then zeroes capability
custody before the final stopped audit. Tests cover descriptor closure and
reuse, epoch mismatch, audit failure, dependency loss, redaction and backing
credential bounds and zeroization; the existing disposable-JetStream suite continues to
qualify exact buckets, restart and rollback rejection.

This increment does not create buckets, provision infrastructure, mint a
credential, expose a listener or send MCP traffic. Those remain later gates.

### RFC-0022 immutable record and deployment-plan review — 2026-08-03

Issue #110 records implementation candidate `1af3ddb` and Git tree
`507a2358fdb17bc48b31e9af68f8d18296754bd8`, together with the successful
repository qualification and the complete reviewed delivery chain. The
redacted plan fixes a single isolated Linux host, a direct private TLS
listener, loopback operations, local replay/audit stores and the delivered
loopback-only NATS composition. It defines separate owner approvals for
provisioning and one live synthetic window, closed review evidence, teardown
and state-preserving rollback.

The review also identifies two pre-provisioning gaps: the repository publishes
no executable entrypoint or artifact, and normal composition disables bucket
bootstrap without providing the separately reviewed accountable bootstrap
operation required by RFC-0022. Those gaps stop provisioning approval. They
must be delivered at a new immutable commit, after which the implementation
record and plan must be reconciled. Publishing the present documents creates
no infrastructure, credential, listener or MCP authority.

### RFC-0022 executable-assembly implementation review — 2026-08-03

Issue #115 adds one closed executable below the existing `internal/`
responsibility. It accepts exactly one absolute supervisor-owned non-secret
configuration path and fixes inherited descriptor slots for the NATS
credential and capability keyring. There are no environment overrides,
subcommands, bootstrap, debug, credential-minting or administration modes.

The application validates configuration, file custody, TLS identity and signed
registration before consuming descriptors. It then owns replay and audit
ledgers, mandatory audit, capability custody, the bootstrap-disabled
JetStream composition, neutral primitives service, HTTP bridge, readiness and
direct TLS runtime. Shutdown removes readiness, closes JetStream, zeroes the
capability key, appends the stopped audit and only then closes the replay and
audit databases. Construction and runtime failures collapse to one fixed
non-sensitive process message.

The workflow builds the executable twice with trimmed paths and embedded Git
revision, requires byte-identical outputs, and continues to run the complete
race/disposable-JetStream qualification. Hermetic assembly tests cover valid
serve/shutdown, descriptor sequencing, closed audit continuity, zeroization,
argument bounds and redacted failure mapping.

This executable still cannot create its three fixed buckets. Accountable
bootstrap issue #117, a superseding immutable implementation record and
deployment-plan reconciliation remain required before provisioning approval. No live listener,
credential, MCP traffic or provider authority is created by #115.

### RFC-0022 offline OCI packaging review — 2026-08-04

Issue #141 adds a deterministic OCI `scratch` packaging boundary for the
selected private Kubernetes operator environment. The layer contains exactly
the two previously reviewed RFC-0022 executables, minimal numeric non-root
identity files and empty working directories. The build verifies both binary
SHA-256 values before packaging and fixes Linux AMD64, UID/GID `65532:65532`,
the service entrypoint, immutable source revision and profile label.

There is no shell, package manager, downloader, source, compiler, CA bundle,
credential or startup wrapper. Bootstrap requires an explicit exact entrypoint
override. Two offline builds must produce identical OCI layouts; qualification
checks every blob digest, the complete layer path allowlist, configuration and
the deterministic SPDX inventory. Kubernetes must separately enforce a
read-only root filesystem, dropped capabilities, no privilege escalation,
fixed mounts and listener isolation.

This increment creates no registry, image push, namespace, Kubernetes object,
credential, listener or network traffic. The OCI digest must be reviewed and
bound into the operator packet before step-5 approval can be requested.

### RFC-0022 Kubernetes descriptor-launcher review — 2026-08-04

Issue #144 closes the mismatch between Kubernetes read-only Secret file mounts
and the accepted inherited-descriptor executable boundary. A compiled static
launcher accepts only `service` or `bootstrap`, exact absolute configuration
and secret-file paths, and selects only the two fixed reviewed child binaries.
It performs no `PATH` lookup or arbitrary execution.

Secret inputs must be bounded regular non-symlink files with no group/world
write permission. The launcher opens with `O_NOFOLLOW|O_CLOEXEC`, verifies
device, inode, mode and size across open, duplicates through collision-safe
temporary descriptors into exact FD 3/4, closes originals and all descriptors
above 4, clears the environment and performs `exec`. Failure emits one fixed
message with no path or secret detail.

The launcher becomes the OCI entrypoint and is covered by the deterministic
layer and SPDX inventory. The service and bootstrap digests remain unchanged;
the OCI manifest, config, layer and SBOM digests are superseded. Kubernetes
must mount immutable Secret keys as exact regular `subPath` files and must not
use the projected-volume symlink paths directly.

This review does not approve image publication, Secret creation, namespace or
workload creation, bootstrap execution, listener exposure or traffic. Those
remain behind the complete operator packet and explicit step-5 gate.

### RFC-0022 Kubernetes PodIP closure review — 2026-08-05

Issue #169 extends the same static descriptor launcher with one closed
`service-kubernetes` mode. It reads one absolute, mode-checked configuration
template and one absolute, mode-checked Downward-API PodIP file. The template
must contain exactly the typed `${YUKH_POD_IP}:8443` public-bind slot; unknown
or duplicate fields remain rejected by the existing closed JSON boundary.

The renderer accepts only a canonical private, non-loopback IP, replaces only
the typed public-bind field and revalidates the complete result through the
existing service parser. It writes a same-directory mode-`0400` temporary file,
syncs and atomically renames it. Exact restart output is accepted; a changed,
empty or partial pre-existing output fails closed and is never overwritten.
The public base URI, secret purposes, descriptor slots, fixed child executable,
empty environment and descriptor cleanup are unchanged.

This removes the runtime PodIP mismatch without a shell, init image, proxy,
`hostNetwork` or second configuration parser. Residual risk remains the
supervisor-owned writable output directory and Kubernetes's correct Downward
API population; unsafe parents, symlinks, modes, public/wildcard/malformed IPs
and ambiguous output deny startup. The source change supersedes the reviewed
launcher and OCI bytes. Registry publication, packet rebinding, target pull,
Kubernetes mutation, Step 5 and traffic require separate renewed authority.

### RFC-0022 PodIP-aware immutable registry rebinding — 2026-08-05

Issue #174 independently reproduces the PodIP-aware delivery from merge commit
`ce607210c8ae9bd71c4d4adfc1414112cb2fa008` and publishes exactly one new
private GHCR version. Provider pull by digest returns byte-identical manifest,
config and layer blobs for manifest
`13b97c16c376d98767123bf78af5c16cb65ab09960b16fec122eb017317fefbe`.
The package remains private, owner-owned and unlinked from a repository; the
prior version is retained as rollback evidence but cannot be selected by the
deployment packet.

The admissible target identity is the digest-qualified reference, never the
publication tag. Residual risk remains the broader operational PAT accepted
for the bounded publication; temporary registry authentication state is
destroyed after provider verification. Rebinding artifact evidence grants no
target pull, Kubernetes mutation, Step 5, MCP request or traffic authority. A
fresh owner approval against the complete packet remains mandatory.

### RFC-0022 non-root runtime-directory closure — 2026-08-05

Renewed Step-5 execution exposed that a kubelet-owned writable volume root
cannot itself satisfy both non-root write access and the launcher's private
output-parent rule. Issue #182 keeps the volume root outside the trusted config
boundary and permits the launcher to create exactly one absent UID-owned
mode-`0700` child beneath an exact mode-`0770`, effective-GID-owned mount root.
An existing private child must have the executing UID and exact mode `0700`.

The child may contain only the expected rendered output or be empty. Symlinks,
wrong mode or owner, world-writable mount roots, unexpected entries and changed
or partial output fail closed. The mount remains visible only to Coordination;
the NATS container does not mount it. The launcher then retains its mode-`0400`
same-directory atomic render and exact-restart behavior.

This closes ownership without a root launcher, init image, shell, capability,
privilege escalation or relaxed output mode. The changed executable and OCI
bytes require another reproducible registry/packet binding before Step 5 may
resume. It grants no credential, listener, MCP traffic or Step-7 authority.

### Accepted RFC-0024 offline trust-ceremony impact — 2026-08-04

RFC-0024 identifies a gate-ordering risk: fabricating or prematurely
creating a signed-registration digest to satisfy the pre-step-5 packet would
either misstate evidence or expire the <=15-minute workload credential before
the no-traffic review. The proposal separates durable trust/policy generation
from ephemeral step-5 identity completion and makes the actual registration
digest mandatory step-6 evidence.

The proposed offline ceremony adds volatile-workspace to encrypted-custody,
logical operator to fresh-reviewer-checkpoint and exact private identity to
public redacted digest boundaries. Controls are network namespace isolation,
swap-excluded plaintext, verified tools, distinct root/leaf/policy purposes,
canonical documents, deterministic SHA-256 evidence, fail-closed destruction
and no partial success.

Residual risks are software-backed custody and one human performing both
logical checkpoints. The ordering and evidence semantics are accepted for the
bounded staging proof, but acceptance creates no key, credential, target or
traffic authority.

### RFC-0024 ceremony-tooling implementation review — 2026-08-04

Issue #149 implements a dependency-minimal offline generator and public-output
verifier. The generator has one closed configuration and one empty volatile
output boundary. It uses Go cryptographic randomness, distinct P-256 root/leaf
and Ed25519 policy keys, fixed staging validity bounds, exact SAN input and
canonical registration/policy artifacts. Private outputs are mode `0400`;
public artifacts are mode `0444`.

Generation is all-or-cleanup on write failure. The closed canonical receipt
contains algorithms, key IDs, validity endpoints and SHA-256 evidence only;
server identity, tenant, principal, private paths and private bytes are absent.
The verifier rejects changed digests, noncanonical documents, invalid chains,
wrong purposes or algorithms. Configuration and operational failures collapse
to one fixed message.

Hermetic tests generate only disposable synthetic identities in test-owned
temporary storage, exercise unsafe configuration/output and tamper paths, and
retain no authority. The executable is built twice with trimmed paths and no
build ID. This implementation does not authorize or perform the real ceremony,
Vaultwarden mutation, target access or secret generation for staging.

### RFC-0022 accountable bucket-bootstrap implementation review — 2026-08-03

Issue #117 adds a second, one-shot administrative executable with no listener,
service runtime, capability key, registration, replay database or audit
database access. It captures exactly one short-lived bootstrap NATS credential
from inherited descriptor 3 before opening its single absolute, closed,
non-secret configuration file. Configuration remains loopback-NATS-only and
fixes the exact replica, retention, lifetime, replay-safety, capability-budget
and positive epoch profile.

The operation reuses the accepted JetStream adapters with bootstrap enabled to
create missing nonce, lease and capability-budget buckets or verify every
immutable property of existing buckets. A mismatch fails closed; the operation
has no update, delete, purge, migration, enumeration, retry, polling or repair
path. It closes the owned connection and descriptor and clears the bounded
credential buffer on every result.

Success emits one canonical, deterministic receipt containing only the closed
schema/profile, embedded source revision, epoch, a SHA-256 digest of the exact
three-bucket profile and `verified`. It contains no endpoint, credential,
provider error, stored key/value or mutable infrastructure detail. Failures
collapse to one fixed stderr line and emit no receipt. Hermetic tests prove
create-then-verify behavior against disposable JetStream and exactly three
bucket streams; reproducible builds embed the source revision.

This increment does not execute against real infrastructure and grants no
credential minting, provisioning, listener, MCP traffic, provider execution,
protected mutation or production authority. A superseding immutable record and
deployment-plan reconciliation remain prerequisites to a provisioning request.

### RFC-0022 immutable candidate reconciliation — 2026-08-03

Issue #129 supersedes the earlier source candidate with commit
`d122f31ce6a74dcec97dfcf8095a4447e23ee593` and tree
`a59ba3f7ad6018d96f7329710eb593766acda676`. That identity contains both the
closed staging service executable from #121 and the separate accountable
bootstrap executable from #127. Post-merge run `30851387901` qualifies the
complete race/disposable-JetStream suite and byte-reproducible builds of both
executables at that exact revision.

The reconciliation closes the two implementation gaps recorded by #110 but
creates no distribution artifact or operator packet. Provisioning remains
fail-closed until separately reviewed evidence binds concrete artifact,
trust, policy, credential-policy, limit, epoch, filesystem and rollback
digests/outcomes to the immutable candidate and the owner explicitly approves
that packet. A live synthetic MCP window remains a second later approval.

MCP #50 may rely on the immutable contract only for disabled-by-default code
and hermetic qualification. No endpoint, credential, bootstrap execution,
listener exposure, MCP request, provider execution, protected mutation or
production authority crosses from this record.

### RFC-0023 transcript lifecycle design review — 2026-08-03

Issue #133 proposes the mandatory single-node lifecycle boundary required by
RFC-0008 before a relay executable may admit events. Every transcript binds a
finite signed policy before sequence 1. Lifecycle administration remains on a
separate SQLite port unavailable to `relay.Store`, public HTTP/SSE, relay
sessions and ordinary publish/replay/watch credentials.

Destructive work is modeled as a monotonic recoverable saga rather than a
false cross-database transaction. Authorization, optional required export,
append-only marker/preimage persistence and external signature attachment all
complete before payload removal. Event, identity and security-audit backup
deletion remain distinct evidenced obligations. Exact retry reconciles one
operation ID; ambiguity never creates a replacement or broadens the target.

Redaction and deletion make the affected transcript non-active and incomplete,
fence append/live delivery and preserve signed evidence that accepted history
existed. Successor epochs are explicit and higher; identifiers are never
reused. Clock rollback, overdue work, contradictory restore state or resurrected
removed payload fences the channel until deterministic recovery completes.

The review also closes an existing read-contract gap: the unreleased RFC-0004
page currently omits lifecycle and refuses non-active lookup. RFC-0023 requires
one explicit pre-release relay/client revision with mandatory lifecycle/policy
fields and signed lifecycle receipt references. No dual-shape compatibility or
route alias may hide non-active state.

This design creates no destructive capability or deployment authority. Its
acceptance would authorize only separately reviewed schemas/port, SQLite,
worker/recovery and hermetic synthetic implementation increments. Real data,
backups, relay deployment, Matrix, MCP and production remain excluded.

### RFC-0023 schema and port foundation review — 2026-08-04

Issue #135 implements only the authority-neutral lifecycle contract. Four
closed schemas fix the finite policy, immutable operation intent, append-only
marker and unsigned administrative receipt preimage. Domain-separated JCS
derivation and public byte-exact vectors prevent an adapter or signer from
reconstructing mutable fields later.

The administrative `TranscriptLifecycleStore` is a distinct Go interface with
typed requests. It neither embeds nor is type-compatible with ordinary
`relay.Store`. Cross-binding validation requires one operation ID and intent
digest across marker, receipt preimage and signature attachment; exact retry
rejects replacement or target broadening. Policy successor validation rejects
epoch rollback, while epoch zero remains valid for already defined protocol
transcripts.

Errors and audit reasons are closed and sanitized. Policy durations are
positive finite JSON-safe integers, selective-redaction targets are sorted and
unique, backup deadlines have an exact three-domain order, saga transitions
are monotonic, and unknown provider detail is rejected by schema and audit
vocabulary tests.

No adapter implements the port in this increment. No SQLite schema, payload
removal, signing key, worker, clock scheduling, backup provider, HTTP/SSE
revision, executable, real data, deployment, Matrix, MCP or production
authority is introduced.

### RFC-0023 SQLite lifecycle preparation review — 2026-08-04

Issue #143 implements only `TranscriptLifecyclePreparationStore`. The SQLite
candidate has no signature, removal, backup or completion methods and cannot
be assigned to the full destructive lifecycle port or to ordinary
`relay.Store`. Exact retention policies enter through a constructor boundary
after offline manifest verification; reservation requires their digest and
epoch to match immutable canonical channel metadata.

STRICT schema version 4 stores canonical policy, immutable intent/digest,
transcript policy binding, export digests, marker and unsigned receipt
preimage. One partial unique index permits only one unfinished operation per
transcript epoch. Exact UUIDv7 retries return the stored operation; changed
intent, target, policy, tenant, channel, epoch or export evidence conflicts
without mutation. Required export evidence gates marker persistence and stores
no provider path, endpoint, account, credential or arbitrary response.

Marker persistence changes transcript lifecycle/completeness and writes the
exact marker/preimage in one `BEGIN IMMEDIATE` transaction. Append checks that
durable lifecycle in its own write transaction and fails closed after the
fence. Forced rollback proves that neither half can survive alone. Generated
temporary-database tests prove concurrency convergence, epoch-zero transcript
compatibility, immutable policy-epoch matching, restart identity, bounded due
inspection, malformed-state rejection and byte-identical payload preservation.

This increment deliberately leaves every accepted payload row intact. It
introduces no signer, destructive worker, clock scheduler, backup provider,
HTTP/SSE mutation handle, executable composition, real data, deployment,
JetStream lifecycle, Matrix, MCP or production authority.

### RFC-0023 verified SQLite primary removal review — 2026-08-04

Issue #152 implements a second capability-segregated adapter for exact
lifecycle signature attachment and synthetic primary-store removal. It accepts
only a public verification port. No signer, private key, backup receipt or
completion method enters the adapter, and the candidate cannot implement the
aggregate destructive store. Verification callbacks run before the SQLite
write transaction; exact persisted bytes are rechecked after acquiring it.

Schema version 5 stores the 64-byte verified signature, one operation removal
digest, digest-only per-sequence tombstones and a separate identifier non-reuse
registry. Receipt digests are globally unique; event digests remain scoped to
tenant/channel identity. Selective redaction deletes only the signed target
rows. Whole deletion deletes only the bound transcript epoch. Both paths
atomically insert tombstones, delete accepted rows and advance to
`payload_removed`; a forced final-state failure rolls the entire transaction
back.

Every retry revalidates operation ID, intent digest, canonical preimage,
signature and removal evidence. Changed or malformed material returns only
closed lifecycle sentinels. A failed or unavailable verifier leaves every
payload intact. Internal replay of a redacted epoch stops before the first
removed sequence; a deleted epoch returns no records. Digest tombstones prevent
raw identifier reuse without retaining removed event, binding, receipt or
participant material.

The candidate claims logical primary-store removal only. Generated canary tests
scan the database, WAL and SHM failure domain and deliberately make no physical
sanitization claim: historical SQLite pages may retain bytes outside the
committed logical view. Media sanitization, backup custody, restore handling,
completion, worker scheduling, HTTP/SSE revision, executable composition, real
data, deployment, JetStream lifecycle, Matrix, MCP and production remain
separately gated.

### RFC-0023 backup and completion contract review — 2026-08-05

Issue #156 replaces the digest-only backup placeholder and
`Complete(OperationReference)` trust shortcut with closed authority-neutral
evidence. Exactly three immutable obligations bind operation, intent, policy,
custody domain, copied deadline and one backup-generation or accepted
absence-manifest digest. Custodian receipts are append-only UUIDv7 evidence,
cross-bind the obligation and backup identity, carry only closed method/outcome
values and must verify through a public Ed25519 verification capability before
they can affect recovery state. No signer or private key crosses the port.

Completion now requires explicit canonical evidence naming the three receipt
digests in event, identity and security-audit order plus accountable audit
receipt and checkpoint references. Missing, reordered, replaced, cross-domain,
unverified or contradictory evidence fails closed. A failure receipt, a success
after its immutable deadline, or a later distinct success after failure remains
an incident: append-only evidence cannot overwrite it or auto-authorize
completion. Incident resolution requires a future accepted contract.

The recovery result exposes only closed status and an ordered bounded list of
per-domain findings. Mixed failure and deadline incidents cannot overwrite one
another. Public verification authority unavailability remains a recoverable
finding and is never mislabeled as contract corruption; invalid signatures and
cross-bound evidence still fail closed. The result cannot carry provider paths,
endpoints, accounts, credentials, arbitrary responses or backup content. This
increment adds no SQLite schema or adapter,
provider call, backup deletion, audit write, worker, scheduler, restore action,
physical sanitization, HTTP/SSE/client authority, executable, deployment,
JetStream lifecycle, Matrix, MCP or production use.

### RFC-0023 SQLite backup and completion persistence review — 2026-08-05

Issue #165 materializes only one caller-supplied canonical set containing the
exact event, identity and security-audit custody obligations. Schema version 6
retains canonical set, obligation, append-only receipt and completion bytes
with domain-separated digests. One obligation per operation/domain, globally
non-reusable receipt IDs and one immutable completion identity prevent silent
replacement. SQLite never discovers a backup, derives an obligation from a
receipt or stores provider paths, accounts, credentials, responses or content.

Custodian signature verification and the narrow lifecycle-completion audit
verification capability run before `BEGIN IMMEDIATE`. The write transaction
performs no external callback: it reloads and byte-compares the exact operation,
set, obligations, receipts and completion request against the verified
preflight snapshot. Verifier unavailability performs no write claiming
verification. Exact concurrent retries converge; changed bindings, reordered
domains, reused identities, skipped states and cross-domain substitutions fail
closed.

Failure receipts, late successes and later distinct attempts remain append-only
incident evidence and cannot advance the operation. Recovery exposes only a
bounded ordered finding per custody domain; malformed persisted evidence is
reported as corrupt without exposing database or evidence detail. Completion
requires three timely verified successes plus explicit audit receipt and
trusted covering checkpoint evidence and advances `backups_pending` to
`completed` atomically.

This adapter implements no preparation, signing, removal or ordinary relay
port. It performs no provider call, audit append, checkpoint creation, worker
scheduling, restore, physical sanitization, real-data operation, deployment,
JetStream lifecycle, Matrix, MCP or production work. Those authorities remain
separately gated.

### RFC-0024 server-leaf rotation tooling review — 2026-08-05

Issue #163 adds a leaf-only path to the existing offline ceremony executable.
It accepts the already reviewed private configuration plus absolute,
mode-checked root key and certificate inputs, proves that the P-256 private key
matches the accepted CA certificate and refuses a root that cannot cover the
complete new 24-hour validity interval. Root material never enters the output.

The command creates exactly one fresh P-256 server key, one root-signed
certificate for the unchanged exact DNS/IP identity and one canonical redacted
receipt. A separate verifier binds the trust-bundle digest, root key ID, exact
SAN shape, chain, algorithm, server-auth use, 24-hour bound and leaf digest.
Unsafe modes, symlinks, malformed or mismatched roots, wrong identity, partial
output and receipt/certificate tamper fail closed.

This tooling does not itself open custody or replace a retained leaf. Private
execution still requires a volatile network-isolated workspace, an atomic
encrypted-custody replacement with rollback to the prior leaf, a fresh reopen
checkpoint and plaintext destruction. It grants no trust-root or policy-key
rotation, registry, target, Kubernetes, Step 5, MCP or traffic authority.

### RFC-0013 verified client publication review — 2026-08-05

Issue #6 adds one provider-neutral publication method to the existing client.
It accepts only bounded JCS-canonical event bytes bound to the configured
channel, authorizes the exact POST target, follows no redirect and maps closed
HTTP outcomes without exposing provider bodies. Success requires a canonical,
cryptographically verified receipt bound to the event digest, event ID,
channel and transcript epoch. Changed targets, cookies, unsigned receipts and
binding mismatches fail closed.

The increment constructs no event, selects no participant, stores no
credential and grants no ownership or execution authority. CLI signal
commands, watch, a public binary, deployment, Matrix and production use remain
separately gated.

### RFC-0013 core event construction review — 2026-08-05

Issue #6 adds explicit builders for `join`, `claim` and `progress`. Configuration
supplies the exact channel, source and visible participant; no environment, Git
state or chat context is consulted. Event and claim identifiers use UUIDv7,
timestamps are canonical UTC milliseconds, collections are explicit and the
complete JCS event must pass the accepted protocol validator before it can be
published.

The builders do not infer ownership, choose work, publish events or access
credentials. Remaining signal families, CLI exposure, Matrix and deployment
remain separate increments.

### RFC-0013 conversation and handoff construction review — 2026-08-05

Issue #6 completes closed builders for question/answer, review/verdict,
handoff offer/accept, release and leave. Root correlations and causal event
references remain explicit. Handoff boundary and empty evidence-set digests
are derived canonically rather than trusted from caller input; acceptance must
repeat the exact offered digests. Every complete envelope passes the accepted
schema and semantic validator.

The builders exchange statements only. They do not select recipients, resolve
claims, accept work, publish, access credentials or grant authority. CLI
exposure, live qualification, Matrix and deployment remain separately gated.

### RFC-0013 signal CLI boundary review — 2026-08-05

Issue #6 exposes the accepted signal command names through a bounded stdin JSON
boundary. Each command decodes one closed type-specific document, constructs a
validated canonical event, publishes it once and returns one closed JSON result
containing generated identifiers and the already verified receipt. Unknown
commands, fields, trailing values, oversized input and protocol conflicts map
to stable codes without provider text.

Builder, authenticated publisher and credential custody remain injected by the
host. This increment adds no executable, ambient configuration, plaintext
credential fallback, retry, recipient selection, ownership inference, Matrix
bridge or deployment.

### RFC-0013 four-agent runtime qualification review — 2026-08-05

Issue #7 composes four independently authenticated CLI runners through the
real TLS handler, authorization boundary, transition validator, append service
and memory Store. The complete join, claim, progress, question, answer, review,
verdict, handoff, successor claim, release and leave sequence produces fifteen
durable records with verified receipts and no user-mediated message copying.

The qualification exposed and closes one transition defect: an accepted
handoff successor starts a new root correlation while causally referencing the
accepted offer. Cross-correlation remains forbidden for every other event, and
the successor is admitted only for the exact recipient of the single accepted
handoff.

This is a hermetic in-process qualification. It adds no insecure server mode,
credential fallback, deployment or production authority and does not yet claim
the required two isolated operating-system processes.

### RFC-0013 isolated-process qualification review — 2026-08-05

Issue #7 starts separate implementation and review operating-system processes,
each holding credentials for only its own two synthetic agents. They discover
cross-session state exclusively by verified replay from the real TLS handler;
the parent starts the sessions and compares evidence but forwards no event ID,
message or protocol state between them.

Both processes independently retain the same sanitized 15-record projection
and SHA-256 digest. The fixture removes generated identifiers, receipts and
transport details while preserving sequence, event type and participant. It
contains no credential or unrestricted transcript.

This remains hermetic qualification with a test-only certificate and memory
Store. It adds no insecure runtime profile, public executable, deployment,
Matrix bridge or production authority.

### RFC-0013 executable boundary review — 2026-08-05

Issue #6 adds the named client process and one closed dispatcher for the
accepted command vocabulary. Help and version work without configuration;
uncomposed read and mutation paths fail with stable JSON and exit codes.

The executable contains no token argument, environment credential discovery,
plaintext session store, permissive receipt verifier or insecure TLS profile.
Bootstrap, credential custody, watch and live network composition remain
required before the process is usable against a relay.

### RFC-0014 client bootstrap saga review — 2026-08-05

Issue #6 composes the neutral bootstrap transaction across one explicit signer
store, external-token source, relay issuer and credential store. Success is
reported only after CAS persistence, exact reload and signer/thumbprint reopen.

A newly created signer is retired only when failure occurs before the relay
exchange. Once the exchange begins, ambiguity retains the signer and never
claims a usable session. Tokens, revisions and private keys remain behind their
closed adapter boundaries and are never formatted or returned.

### RFC-0026 macOS Keychain custody boundary review — 2026-08-05

Issue #6 adds an independently injected `macos-keychain-v1` profile with one
exact Keychain generic-password root item and the existing encrypted local
SQLite custody store. Profile selection remains closed configuration; no
executable path infers an operating system, discovers a provider, or falls
back to Linux, files, plaintext, environment credentials, or another profile.

The adapter uses only an exact class/service/account/(optional access-group)
Keychain query with authentication UI disabled. It rejects ambiguous, malformed,
locked, authorization, UI, accessibility, and provider outcomes. Missing root
material cannot be created when a custody database already exists, preventing a
replacement root from making encrypted state appear newly valid. The external
token and direct HTTPS transport remain caller-injected. Native Keychain
integration qualification against supported macOS releases remains outstanding.

## Formal design record

RFC-0002 freezes the following repository-only design decisions when accepted:

1. identity and authenticator abstraction, with delegation explicitly excluded;
2. tenant/channel ownership, admission, and administrative authority;
3. receipt canonicalization, signature promise, and key ownership;
4. retention, redaction, deletion, and backup semantics;
5. persistence/isolation topology and atomic acknowledgement boundary.

The accepted record must also name the security owner, tenant/channel administrative authority, relay operator, relay security administrator, evidence verifier, and residual-risk acceptors. RFC-0002 acceptance satisfies the design-decision requirement only; exact implementation topology and qualification remain issue #5 gates and no relay deployment is authorized.

Federation/offline replay requires a future decision and is excluded from the MVP.
