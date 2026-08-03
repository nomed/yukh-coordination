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

## Formal design record

RFC-0002 freezes the following repository-only design decisions when accepted:

1. identity and authenticator abstraction, with delegation explicitly excluded;
2. tenant/channel ownership, admission, and administrative authority;
3. receipt canonicalization, signature promise, and key ownership;
4. retention, redaction, deletion, and backup semantics;
5. persistence/isolation topology and atomic acknowledgement boundary.

The accepted record must also name the security owner, tenant/channel administrative authority, relay operator, relay security administrator, evidence verifier, and residual-risk acceptors. RFC-0002 acceptance satisfies the design-decision requirement only; exact implementation topology and qualification remain issue #5 gates and no relay deployment is authorized.

Federation/offline replay requires a future decision and is excluded from the MVP.
