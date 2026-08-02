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
- agent or session acting for a principal;
- channel administrator;
- relay operator;
- external authority or governance system;
- evidence host and independent verifier;
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
- `participant_id`: unique person/session/agent instance bound to that principal for a credential or connection lifetime;
- `display`: mutable, non-unique advisory text.

Client assertions MUST NOT establish authenticated identity. The relay rejects or overwrites asserted principal bindings and records authentication context in the receipt, never credentials. Delegation and session lineage are explicit; kind and display never imply trust.

The reference MVP supports TLS plus one configured authenticator behind a provider-neutral interface. Identity from event bodies, forwarded headers, display names, or presence is rejected for authorization.

### Admission and channel administration

Admission is deny-by-default and separate from work authority. Channel creation and membership are administrative policy outside the protocol event log.

Every create, publish, read, watch, replay, export, redact, and delete action is authorized against `(tenant, channel, principal, action)` before existence is disclosed or state changes. Claim, presence, review, verdict, and handoff events never alter ACLs.

### Tenant and channel isolation

Tenant identity is relay-derived. Channels use immutable internal IDs bound to exactly one tenant. Storage and index keys begin with tenant ID; every query includes tenant and channel predicates. External names and cross-channel references cannot bypass scope.

Denied access MUST NOT reveal whether a tenant, channel, event, participant, cursor, or evidence reference exists.

### Validation, append, and replay

The relay enforces closed schemas, version allow-lists, canonical lexical formats, safe Unicode, and frozen size/count/depth/string limits before persistence.

The relay assigns receive time and a monotonically increasing sequence within one tenant/channel log. Client time and IDs do not establish order, expiry, ownership, or authorization.

Event append, authenticated binding, sequence assignment, idempotency record, event digest, and receipt commit atomically. No success receipt is returned before commit. Exact duplicate bytes are idempotent; same ID with different bytes is rejected and security-audited.

Replay cursors are tenant/channel scoped and opaque or integrity-protected. Page size, replay window, connection count, and processing time are bounded.

### Impersonation and handoff

Display collisions are allowed but visibly disambiguated by principal and participant bindings. Reconnect cannot silently reuse an old participant identity.

Handoff acceptance must be emitted by the exact authenticated recipient named by the offer and bind the source claim generation, channel, work identity, boundary digest, and evidence-set digest. Release, supersession, changed boundary, late acceptance, or competing acceptance yields a deterministic diagnostic and no authoritative transfer.

### Evidence and SSRF

The core relay stores evidence URI, media type, digest/revision, declared size, and advisory description. It MUST NOT fetch arbitrary evidence URIs.

Verification occurs under a separate client/verifier policy. Digest mismatch, unavailable content, unauthorized retrieval, mutable content, and unknown algorithms remain explicitly unverified. A digest proves bytes, not truth or authorization.

Credential-bearing URLs, inline evidence bodies, private prompts, unrestricted logs, and secrets are prohibited.

### Privacy, retention, and redaction

Channels are private by default and have no public directory. Event bodies prohibit credentials, secrets, private prompts, unrestricted logs, and personal or special-category data. Operational logs redact authorization material and exclude bodies by default.

A finite tenant/channel retention period MUST be configured before accepting events. Accepted payloads are not silently edited.

The MVP supports:

- immediate access revocation;
- whole-transcript export;
- explicitly audited destructive transcript deletion;
- selective redaction only through an append-only marker plus payload removal/restriction, preserving minimal integrity metadata.

Backups and replicas publish a bounded deletion window. The project MUST NOT promise both permanent full payloads and erasure.

### Receipts and signing

Client signatures are excluded from the MVP unless offline/federated verification is promoted later.

Authenticated transport and relay-attributed durable receipts are required. If the project claims transcripts are verifiable outside the relay, receipts are signed with a relay-owned asymmetric key stored outside the event database. Key ID, rotation overlap, revocation, public verification material, and compromise window are documented.

A database-local HMAC or a key in the same compromise domain is insufficient for independent verification.

### Denial of service and abuse

The implementation enforces per-principal, tenant, and channel quotas; event/evidence size limits; bounded depth and string length; replay/window limits; connection and concurrency limits; timeouts; and backpressure.

Compressed payload expansion, log injection, high-cardinality telemetry, public URL fetching, and unbounded channel discovery are prohibited. Admission and administration use stricter limits than ordinary publication.

### Security audit

A restricted security audit log records authentication/authorization decisions, ACL and administrative changes, rejected writes, rate limiting, key lifecycle, export, redaction, deletion, and incident actions. It excludes credentials and event bodies by default and correlates to event/receipt IDs.

The protocol transcript is not the complete security audit log.

## STRIDE threat register

| Threat | Example | Required mitigation | Residual risk / evidence |
|---|---|---|---|
| Spoofing | B declares A's participant/display | relay-derived principal binding; display never authorizes | negative fixture proves receipt binds B |
| Tampering | same event ID with changed bytes | canonical digest; atomic idempotency collision rejection | collision appears only in restricted audit |
| Repudiation | participant denies a handoff statement | durable attributed receipt; optional external receipt signature | compromised-relay window remains disclosed |
| Information disclosure | cross-tenant channel guessing | authorize before lookup; tenant-prefixed storage/query | negative test reveals no existence oracle |
| Denial of service | replay exhaustion or deep payload | quotas, bounds, pagination, timeouts, backpressure | load thresholds and rejection telemetry |
| Elevation of privilege | claim or handoff modifies ACL/authority | protocol events never change access or work authority | external policy receipt required |
| SSRF | evidence URI targets internal service | relay never fetches evidence | verifier has separate egress policy |
| Replay | duplicate/late handoff acceptance | atomic event idempotency and claim-generation precondition | deterministic invalid-transition diagnostic |
| Operator compromise | transcript or key manipulation | separated admin/signing access, audit and key rotation | post-compromise attribution explicitly suspect |
| Privacy failure | permanent payload conflicts with erasure | finite retention, audited deletion/redaction, backup window | integrity metadata may remain by policy |

## Fail-closed conditions

No durable acceptance and no success receipt are permitted when authentication, authorization, tenant resolution, required signing, schema validation, idempotency lookup, storage commit, or sequence assignment is uncertain.

Authentication or ACL provider timeout, signing-key unavailability, partial persistence, and ambiguous tenant/channel binding return non-enumerating temporary failures.

## Required negative evidence

Issue #3 cannot close without executable cases for:

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

## Decisions blocking acceptance

Separate ADRs or an accepted security RFC must freeze:

1. identity, delegation, and authenticator abstraction;
2. tenant/channel ownership, admission, and administrative authority;
3. receipt canonicalization, signature promise, and key ownership;
4. retention, redaction, deletion, and backup semantics;
5. persistence/isolation topology and atomic acknowledgement boundary.

Federation/offline replay requires a future decision and is excluded from the MVP.
