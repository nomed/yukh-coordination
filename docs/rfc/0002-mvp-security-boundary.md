# RFC-0002: MVP security boundary

- Status: Draft
- Governing issue: #3
- Date: 2026-08-02
- Scope: repository-only protocol and reference-relay design boundary

## Summary

This RFC freezes the minimum security decisions required to design the Yukh Coordination MVP. It consolidates the owner-approved identity, admission, receipt, retention, persistence, and isolation boundaries.

It is governed by [ADR-0001](../adr/0001-protocol-not-control-plane.md), aligns with [RFC-0001](0001-protocol-v0.1.md) from governing issue #2, and is supported by the detailed [MVP threat model](../security/threat-model.md). RFC-0001 remains responsible for the protocol envelope, canonical event representation, signal schemas, and compatibility contract; this RFC constrains their security semantics. The RFC-0001 link resolves when the issue #2 record is integrated; this branch does not duplicate or redefine that record.

This Draft does **not** authorize implementation, a production identity provider, relay operation, deployment, public admission, or production use.

## Context

Participants in isolated sessions need attributable, replayable coordination without granting the relay execution authority. A relay that trusted display identity, client-selected tenancy, mutable channel names, ambiguous acknowledgements, or undeclared retention would make the transcript misleading precisely when it is most needed.

The security boundary therefore distinguishes authenticated identity from presentation, administrative access from work authority, accepted bytes from evidence truth, and protocol design from deployment qualification.

## Decision 1: identity, delegation, and authentication

The relay derives a stable `principal_id` from an authenticated subject. It issues a unique `participant_instance_id` and monotonically distinct `session_epoch`, bound to that principal, tenant, authentication context, and creation time. Clients cannot select, transfer, or resurrect those bindings. Reconnection creates a new instance/epoch unless the relay validates a narrowly scoped, integrity-protected resume capability.

`display`, participant kind, presence, and event-body identity are advisory and never authorize. Delegation and session lineage are explicit bindings; neither is inferred from names, ordering, or model/runtime type.

The reference design uses TLS and one configured authenticator behind a provider-neutral abstraction. Credentials remain transport-only, are never persisted in events or receipts, and are redacted from operational and security logs. Authenticator or identity-binding uncertainty fails closed.

## Decision 2: tenant/channel administration and admission

Tenant identity is relay-derived. Each channel has one immutable internal ID, one tenant binding, and one registered canonical channel URI. URI aliases, reassignment, and network dereference during canonicalization are excluded from the MVP.

Admission is deny-by-default and separate from protocol-observable work claims. An accountable tenant administrator owns tenant policy and appoints accountable channel administrators. Channel administrators own membership, retention, export, redaction, and deletion decisions within their delegated scope.

Every create, publish, read, watch, replay, export, redact, and delete operation is authorized against `(tenant, channel, principal, action)` before existence is disclosed or state changes. Each authorization decision binds a versioned ACL policy and produces an immutable decision receipt containing policy version/digest, principal, action, resource, result, decision time, and administrator or decision-engine identity. Coordination signals cannot change ACLs or external execution authority.

Unknown and unauthorized resources return the same bounded, non-enumerating external failure posture. Detailed causes are restricted to the security audit.

## Decision 3: canonical signed receipts and key lifecycle

Every durable append has a canonical, domain-separated receipt payload containing:

- protocol and receipt versions;
- tenant ID, internal channel ID, and registered canonical channel URI;
- transcript epoch and server sequence;
- event ID and canonical event digest;
- authenticated principal ID, participant instance ID, and session epoch;
- ACL policy version/digest and decision-receipt reference;
- receive time, append outcome, and signing key ID.

RFC-0001 must freeze the exact byte serialization used by the event digest. RFC-0002 conformance fixtures must freeze the receipt bytes, signature input, signature algorithm, and verification outcomes across implementations.

Receipts are signed with a relay-owned asymmetric key operated outside the event database and its backup/restore failure domain. The lifecycle publishes key IDs, algorithms, public verification material, activation and retirement windows, overlap, revocation, and compromise intervals. Database-local HMACs and keys restored with the event database do not provide independent receipt verification.

Signing-key unavailability prevents a success acknowledgement. It does not erase an already committed append; exact retry returns the same committed outcome when it can be signed. Client signatures, federation, and offline ingestion are excluded from the MVP.

## Decision 4: mandatory retention and transcript lifecycle

A finite channel retention policy is explicitly configured and decision-receipted before the first accepted event. There is no implicit or inherited default. The policy freezes active retention, backup deletion window, export permissions, redaction/deletion authority, and the minimal integrity metadata retained after payload removal.

Every new channel history begins a monotonically distinct `transcript_epoch`. Replay and export identify their epoch and exactly one deterministic completeness state:

- `complete`;
- `incomplete`, with missing sequence boundaries and reason;
- `redacted`, with redaction-marker references;
- `deleted`, with only the deletion receipt permitted by policy.

Epochs cannot be silently joined. Missing data cannot mean “never accepted,” and removed identifiers cannot be reused to manufacture continuity. Accepted payloads are not silently edited. Selective redaction uses an append-only marker plus payload removal or restriction; whole-transcript deletion is explicit, destructive, and audited. Retention expiry, backup restore, redaction, deletion, and epoch rollover produce administrative and security-audit evidence.

Callers and their accountable data owners remain responsible for classifying and minimizing secrets, personal data, regulated data, and private evidence before submission. Relay validation is defense in depth, not a transfer of data-controller responsibility.

## Decision 5: persistence, isolation, and acknowledgement

Event bytes, authenticated identity binding, transcript epoch, server sequence, idempotency record, event digest, and append outcome commit atomically before acknowledgement. A crash before commit yields no accepted event. A crash after commit but before response may lose the ACK; retry with the same event ID and exact canonical bytes returns the same committed outcome and receipt identity. The same ID with different bytes conflicts. If commit state cannot be proven, the relay returns an indeterminate non-success response and cannot create a replacement event or advance observable ownership.

Authentication, admission policy, relay compute, event persistence, security audit, receipt signing, backup, and evidence verification are explicit failure domains. The relay security administrator owns logical isolation; the tenant administrator accepts tenant-specific residual risk. Signing is outside the event-database failure domain, and evidence verification is outside relay admission/write transactions.

All storage and queries are scoped by relay-derived tenant and immutable channel identity. Shared compute or storage constitutes logical isolation only. It cannot be represented as hardened production tenancy without exact-topology evidence for cross-tenant denial, credential separation, restore behavior, operator access, resource exhaustion, and compromise blast radius.

## Claim, handoff, and evidence alignment

A claim binds canonical channel URI, canonical work URI, claimant principal, participant instance/session epoch, and claim generation. A handoff acceptance binds the intended authenticated recipient, source claim generation, work and channel identity, boundary digest, and evidence-set digest. Release, supersession, changed boundary, late or competing acceptance, and wrong session epoch produce deterministic invalid-transition diagnostics and no observable transfer.

`evidence_verification` is an independently authenticated durable statement. It binds verifier identity, evidence URI, algorithm, expected and observed digest or unavailability reason, verification time, verifier-policy version, and result. It neither rewrites the evidence declaration nor automatically changes a claim, review, verdict, or handoff. Evidence bytes and verdicts remain statements, not relay-granted truth or authority.

## Accountability

The design and every candidate deployment name:

- security owner and incident commander;
- tenant and channel administrators;
- relay operator and relay security administrator;
- evidence verifier owner;
- tenant-specific and protocol-wide residual-risk acceptors.

Threats record severity, likelihood, treatment, owner, residual risk, and acceptor. Tenant administrators may accept tenant-specific residual risk. Protocol-wide risk requires project-governance acceptance.

## Qualification gates

Issue #4 must supply byte-exact schemas/fixtures and negative conformance evidence for identity spoofing, cross-tenant access, URI mapping, ACL policy receipts, canonical receipt signing, duplicate/collision/replay behavior, wrong-recipient and stale-epoch handoffs, evidence non-dereference and verification, non-enumerating errors, retention states, and limits.

Issue #5 must supply exact-candidate implementation evidence for atomic append and ACK loss, crash/restart and restore, signer separation and key lifecycle, ACL/authenticator/store/signing outages, transcript epoch continuity, retention/redaction/deletion, backup deletion windows, security audit, quotas/denial of service, credential separation, operator access, cross-tenant isolation, and compromise blast radius.

Neither a green conformance suite nor a working relay alone authorizes deployment. The exact implementation, configuration, component identities, limits, topology, evidence sink, review, and accountable risk acceptance must be recorded before any later deployment decision.

## Deferred decisions

Production IdP lifecycle, SCIM, workload/delegated identity, federation, offline ingestion, end-to-end encryption, HSM/KMS ceremonies, public channels, data residency, legal hold/DSAR automation, external transparency logs, multi-region recovery, and formal penetration testing are outside the MVP and require later decision records.

## Status and consequences

This RFC remains Draft until accountable review accepts it together with the threat model and its alignment with RFC-0001. While Draft, it is a design constraint and review target, not a public compatibility or security claim.

Acceptance would freeze only the repository-owned MVP security boundary. It would not authorize issue #5 implementation, select a deployment topology, accept qualification evidence, provision credentials, publish a service, or approve production use.
