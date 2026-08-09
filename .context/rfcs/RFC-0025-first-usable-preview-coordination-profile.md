# RFC-0025: First usable preview Coordination profile

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-09
- Accepted: 2026-08-09
- Governing issue: #195
- Governing suite issue: `nomed/nomed.github.io#40`
- Governing suite architecture: accepted `nomed.github.io` RFC-0005 on `main`
  at `12d9215f10c4b7fb1762a5025367e3e81543800f` through PR #42
- Governing Coordination architecture: RFC-0002, RFC-0003, RFC-0006,
  RFC-0009 through RFC-0017, RFC-0019, RFC-0021 through RFC-0024

## Decision

Accept one explicitly non-production Coordination profile for the first usable
Yukh suite preview. The profile composes:

- the RFC-0006 JetStream relay command log;
- the accepted relay HTTP/SSE, bootstrap and signed-receipt boundaries;
- two isolated client sessions with independent credential custody;
- two effect-specific instances of the accepted nonce and fenced-lease service;
- mandatory audit, public evidence and deterministic verification boundaries;
  and
- one bounded whole-sandbox teardown lifecycle.

This RFC is required because no earlier accepted Coordination record authorizes
that composition. RFC-0006 qualifies the distributed relay adapter but not a
distributed executable profile. RFC-0022 selects one private staging primitives
identity and no relay. RFC-0023 explicitly excludes JetStream lifecycle.
Accepted client records do not select a preview bootstrap authority or a
container lifecycle. Treating those records as implicit suite-preview authority
would cross security and component boundaries without review.

The project owner explicitly accepted RFC-0025 in #195 on 2026-08-09 by stating
"Accetto tutti e tre", including this Coordination RFC at review-clean proposal
head `d06820bd1444acffc1190620cb681f2d1837777a`.

Acceptance authorizes only a separately reviewed, execution-forbidden
implementation and hermetic synthetic qualification. It does not authorize
infrastructure provisioning, OCI publication, credential creation outside a
test-owned ephemeral process, live traffic, GitHub mutation, provider
registration or execution, preview publication, production use or a
production-readiness claim.

## Profile identity and ownership

The accepted profile identifier is:

```text
yukh-coordination/first-usable-preview-v1
```

Yukh Coordination owns only:

- the component-local container sandbox profile;
- relay and primitives configuration contracts;
- Coordination client bootstrap and receipt/replay verification;
- Coordination conformance and adversarial fixtures;
- Coordination evidence redaction and teardown evidence.

Yukh Projects continues to own Effect A planning, approval binding, controlled
apply, verification and restore. Yukh MCP continues to own Effect B capability
definition, admission, provider invocation, audit, verification and result
release. `nomed.github.io` owns the cross-suite compatibility matrix, maturity
statement and evidence index.

The Coordination sandbox controller may start, stop and inspect only
Coordination-owned processes and test resources. It cannot create a Projects
plan, approve either effect, invoke a protected provider, interpret effect
success, restore a GitHub target or accept the suite preview.

## Sandbox boundary

One run uses an isolated container network and test-owned ephemeral storage. It
is assembled only from exact immutable candidate artifacts and one canonical run
manifest. The Coordination slice contains:

| Boundary | Required profile |
| --- | --- |
| Relay persistence and live wake-up | one RFC-0006 command-log stream in a dedicated NATS account |
| Relay identity and policy | one preview-only, signed, finite manifest and isolated per-run bootstrap authority |
| Relay security evidence | one separate RFC-0011-compatible audit ledger |
| Relay receipt signing | one separate per-run signer service; private key never enters relay or event storage |
| Effect A primitives | one RFC-0015 service instance with its own NATS account, three RFC-0012/0019 buckets, epoch, workload identity, audit ledger and capability key |
| Effect B primitives | a second independently configured instance with no credential, account, bucket, epoch, capability key or audit chain shared with Effect A |
| Clients | two isolated processes, each with one RFC-0014 custody profile and one relay participant identity |
| Operations | loopback-only health/evidence surfaces unavailable to effect workloads |

One NATS server process may host the three accounts for a hermetic run, but
account credentials and subject permissions are distinct. The relay account
cannot access primitives buckets. Neither primitives account can access the
relay stream or the other effect's buckets. NATS subjects, credentials,
consumers, revisions and storage paths remain adapter-private.

No workload receives broker credentials. No container receives a host socket,
container-runtime socket, source checkout, ambient cloud credential, shell
history or unrestricted writable host path. Provider-specific adapters stay
outside the neutral relay and primitives cores.

The canonical run manifest fixes exact artifact digests, profile versions,
conformance-corpus digest, logical service identities, maximum sandbox lifetime,
resource bounds and expected teardown target. It contains no secret. Unknown
members, movable tags, unpinned images, implicit defaults and environment
overrides fail before any process starts.

## Ephemeral identity and bootstrap

The preview is not an insecure development mode. A hermetic qualification run
uses a closed preview-only identity authority reachable only inside the isolated
network. It creates fresh, run-scoped signing material in test-owned volatile
storage and issues only the exact short-lived, DPoP-bound identities declared by
the run manifest.

Two relay clients bootstrap independently through RFC-0009. Each client has:

- a distinct external access token, P-256 proof key, participant profile,
  credential-store record and relay session;
- a distinct principal, participant instance and session epoch;
- a maximum relay session lifetime of 15 minutes;
- no shared token, key, custody record, cache or process memory.

The preview authority cannot issue a provider credential, Projects approval,
MCP capability or primitives workload registration. Its trust root and private
material are never compiled into a normal executable, accepted from repository
content or reused across runs. No allow-all, bearer fallback, fixed universal
token or disabled signature verification is permitted.

Effect A and Effect B each use a separate RFC-0022-shaped short-lived DPoP
workload registration against their own primitives instance. RFC-0022 itself is
not reused as deployment authority: its one-identity private staging profile,
operator packet, credentials, trust material, buckets and approvals remain
independent and inaccessible.

Credential generation and use belong only to a later hermetic test after
implementation is separately approved. This governance record creates no key,
token, certificate, registration or credential.

## Client receipt and replay verification

No Coordination client action is successful merely because HTTP returned
`2xx`, JetStream acknowledged a message or a process exited zero. Each client
must:

1. validate the closed response media type and canonical bytes;
2. verify the receipt signature against the exact run-scoped public key;
3. verify event ID, canonical event digest, channel identity, transcript epoch,
   authenticated participant binding, ACL decision reference and sequence;
4. retain only the verified cursor and bounded public receipt material;
5. replay from the last verified cursor after reconnect;
6. reject gaps, changed bytes, unknown keys, compromise intervals, unsigned
   boundaries and lifecycle ambiguity without advancing state.

The two isolated clients must independently reproduce the same final canonical
Coordination projection digest. The comparison process receives only verified
public records; it cannot forward event IDs, handoff values or protocol state
between clients while the mission thread is running.

Receipt verification proves relay attribution and byte integrity only. It does
not approve a Projects plan, admit an MCP capability or verify either provider
effect.

## Independent nonce and lease domains

The suite RFC requires Effects A and B to remain independent. The preview
therefore uses separate primitives instances rather than extending RFC-0022's
single registered workload into a shared multi-effect authority.

Each effect has its own closed canonical authority-binding schema. The schemas
do not use an `approval_identity`, `lease` or other shorthand object whose
contents can vary outside canonical comparison.

The **Effect A binding schema** contains exactly:

- exact repository identity;
- exact Project identity;
- exact item identity;
- exact ordered operation scope;
- exact policy commit;
- exact immutable Projects producer release;
- exact fresh precondition snapshot identity;
- exact plan identifier;
- exact canonical plan digest;
- exact ordered operation-set digest;
- a canonically absent MCP capability-definition digest;
- a canonically absent MCP provider-implementation digest;
- exact environment identity;
- exact protected-workflow identity;
- exact approval issuer;
- exact authenticated approval subject or principal;
- exact approval issued-at time;
- exact approval expiry time;
- exact unique approval nonce;
- exact domain-separated Effect A nonce `scope_digest`;
- exact Projects component-scoped idempotency key;
- exact Coordination transcript epoch;
- exact Effect A primitives-service restore epoch;
- exact Effect A lease resource identity and holder identity;
- exact Effect A fencing token or lease generation;
- exact Effect A lease expiry and required remaining-freshness bound;
- exact Projects verifier identity; and
- exact declared Projects postconditions.

The **Effect B binding schema** contains exactly:

- exact repository identity;
- exact Project identity;
- exact item identity;
- exact ordered operation scope;
- exact policy commit;
- exact immutable MCP and Projects producer releases;
- exact fresh precondition snapshot identity;
- exact plan identifier;
- exact canonical plan digest;
- exact ordered operation-set digest;
- exact MCP capability-definition digest;
- exact MCP provider-implementation digest;
- exact environment identity;
- exact protected-workflow identity;
- exact approval issuer;
- exact authenticated approval subject or principal;
- exact approval issued-at time;
- exact approval expiry time;
- exact unique approval nonce;
- exact domain-separated Effect B nonce `scope_digest`;
- exact MCP component-scoped idempotency key;
- exact Coordination transcript epoch;
- exact Effect B primitives-service restore epoch;
- exact Effect B lease resource identity and holder identity;
- exact Effect B fencing token or lease generation;
- exact Effect B lease expiry and required remaining-freshness bound;
- exact MCP verifier identity; and
- exact declared MCP postconditions.

Every field is represented directly in the closed schema, canonicalized with
the complete binding and exact-equality checked before provider invocation. The
two effects use distinct complete canonical bindings, binding digests and
effect-specific authority artifacts. Distinct artifacts include precondition
snapshot identities, nonce scope/value digests, lease resources, holders and
fences, plan identifiers and digests, approvals and approval nonces, component
idempotency keys and verifier identities; none may be reused by the other
effect.

Compatibility-scope fields such as repository and Project identity may
intentionally be equal when each independent binding explicitly contains,
canonicalizes and verifies the exact same value. Shared fields are never
inherited by reference or treated as implicit authority. The effects must use
different target item identities and/or disjoint ordered operation sets. If
they share a target, their operation sets must be disjoint, and no operation on
that target may be authorized by both bindings. The two canonical absence
markers in Effect A are schema constants, not reusable authority values,
wildcards or omitted comparisons.

The Coordination transcript epoch and primitives-service restore epoch are
independent canonical fields. The transcript epoch scopes relay records and
replay. The effect-specific primitives restore epoch scopes nonce values, lease
records, sealed capabilities and fencing validity under RFC-0012 and RFC-0015.
Neither value can default from, equal by implication to or substitute for the
other. Effect A and Effect B use distinct primitives restore epochs even when
their relay statements share one Coordination transcript epoch.

Lease acquisition uses a closed effect-specific pre-lease projection containing
the exact repository, Project, item, operation scope, policy commit, producer
release, snapshot, ordered operation-set digest, applicable capability/provider
digests, environment, workflow, derived effect-specific nonce `scope_digest`,
component idempotency key, Coordination transcript epoch, effect-specific
primitives restore epoch, intended holder, verifier and declared postconditions.
A plan identifier, plan digest, approval fields and observed lease state do not
yet exist and are therefore not members of this non-authorizing projection. The
projection derives only the requested lease resource and holder identities; it
grants no invocation authority.

Each nonce `scope_digest` is derived before the pre-lease projection from a
closed effect-specific nonce-scope projection. That source projection contains
exactly the corresponding pre-lease fields except the derived `scope_digest`
itself. It is non-authorizing and prevents circular derivation. The resulting
lowercase SHA-256 digest is not caller-selected: it is inserted into the
pre-lease projection and thereafter treated as an exact authority field.

After acquisition, the planner creates a fresh plan that binds the exact
lease resource identity, observed fencing token or lease generation, exact lease
expiry and required remaining-freshness bound together with every pre-lease
field. The final plan identifier and canonical plan digest then enter the
binding. The plan and approval therefore bind both the Coordination transcript
epoch, the independent effect-specific primitives restore epoch and the exact
effect-specific nonce `scope_digest`. The approval binds that exact plan and all
explicit approval fields. The resulting complete canonical Effect A or Effect B
binding is the sole authority-bearing object evaluated at invocation.

The derivations are:

```text
effect_a_nonce_scope_digest = SHA-256(
  "yukh-suite-preview:effect-a:nonce-scope:v1\n" ||
  canonical_effect_a_nonce_scope_projection
)
effect_a_lease_resource = SHA-256(
  "yukh-suite-preview:effect-a:lease-resource:v1\n" ||
  canonical_effect_a_prelease_projection
)
effect_a_lease_holder = SHA-256(
  "yukh-suite-preview:effect-a:lease-holder:v1\n" ||
  canonical_effect_a_prelease_projection
)
effect_a_nonce_value = SHA-256(
  "yukh-suite-preview:effect-a:nonce:v1\n" || canonical_effect_a_binding
)

effect_b_nonce_scope_digest = SHA-256(
  "yukh-suite-preview:effect-b:nonce-scope:v1\n" ||
  canonical_effect_b_nonce_scope_projection
)
effect_b_lease_resource = SHA-256(
  "yukh-suite-preview:effect-b:lease-resource:v1\n" ||
  canonical_effect_b_prelease_projection
)
effect_b_lease_holder = SHA-256(
  "yukh-suite-preview:effect-b:lease-holder:v1\n" ||
  canonical_effect_b_prelease_projection
)
effect_b_nonce_value = SHA-256(
  "yukh-suite-preview:effect-b:nonce:v1\n" || canonical_effect_b_binding
)
```

Because each pre-lease projection contains its exact primitives restore epoch,
every lease-resource and lease-holder digest binds that epoch. Because each
final binding contains the same epoch, every nonce-value digest binds it again.
A restore-epoch substitution therefore changes every derived identity and
cannot preserve a valid capability or lease under unchanged bytes.

The Effect A and Effect B nonce-scope domain strings, source projections and
digests are distinct. The derived `scope_digest` and `value_digest` form the
exact RFC-0015 nonce authority pair. A requester may not submit a structurally
valid alternative scope with an approved value. Before a nonce service call,
the protected consumer derives the expected scope and value from authenticated
canonical inputs and requires exact equality with the plan, approval, final
binding and request body. Because the pre-lease projection contains the derived
`scope_digest`, both lease-resource and lease-holder derivations bind it.
Because the final binding contains it, the nonce `value_digest` derivation binds
it as well.

Even identical source bytes therefore produce different effect and purpose
digests. A future implementation may not select field names, canonical
representations or derivation domains ad hoc. Conformance vectors must freeze:

- both closed final binding schemas, the two pre-lease projections and the two
  nonce-scope projections;
- canonical positive bytes for Effect A and Effect B;
- every field-level wrong, missing, reordered and substituted negative;
- cross-effect negatives that attempt to reuse a binding digest, precondition
  snapshot, nonce scope/value, lease resource/holder/fence, plan
  identifier/digest, approval, approval nonce, component idempotency key or
  verifier identity;
- every domain string and nonce-scope, lease-resource, lease-holder and
  nonce-value digest;
- distinct transcript/restore epoch values, cross-substitution negatives and
  restore-epoch increment invalidation;
- changed-scope vectors that hold the approved nonce `value_digest` constant,
  require denial before a second primitives call and prove no second `consumed`
  outcome or terminal nonce record is created;
- valid vectors in which repository and Project identity are shared while the
  effect targets differ and/or their ordered operation sets are disjoint and
  every effect-specific authority artifact remains distinct;
- negative vectors that reuse a precondition snapshot, plan, approval, nonce,
  lease, idempotency key, verifier identity or complete binding across effects
  despite a shared repository or Project;
- fencing generation, lease expiry and remaining-freshness boundaries; and
- exact-equality outcomes before any consumer can use the profile.

For each effect:

1. derive the effect-specific nonce `scope_digest`, insert it into the canonical
   pre-lease projection and require exact local equality before any primitives
   call;
2. derive and acquire only the lease resource and holder named by that canonical
   pre-lease projection, with no implicit retry;
3. materialize a fresh plan containing the observed fencing token or lease
   generation, lease expiry and freshness requirement;
4. obtain an approval whose explicit issuer, authenticated subject or principal,
   issued-at, expiry and unique nonce bind that exact plan;
5. construct and canonicalize the complete Effect A or Effect B binding;
6. reconstruct the complete canonical binding from authenticated plan,
   approval, snapshot, environment, nonce and lease inputs immediately before
   invocation;
7. require byte-for-byte equality for the complete binding and exact equality
   for every individual field;
8. require the live primitives service and opened capability to report the exact
   effect-specific restore epoch bound by the plan and approval, independently
   of the Coordination transcript epoch;
9. derive the nonce `scope_digest` and `value_digest` again from the authenticated
   canonical inputs and require exact equality with the plan, approval, final
   binding and closed RFC-0015 request body before sending that body;
10. consume exactly that `(scope_digest, value_digest, epoch)` tuple; treat
    `replayed` as non-success and deny a changed scope before any second service
    call so it cannot create a second `consumed` outcome;
11. require the observed lease resource, holder, fencing token or generation and
   expiry to equal the binding and satisfy the bound remaining-freshness rule;
12. forbid provider invocation on replay, changed bytes, stale approval,
   insufficient lease freshness, ambiguous state or any unequal field;
13. treat provider acknowledgement as non-verifying;
14. permit explicit release only after verified completion;
15. record a possible effect with lost or ambiguous response as
    `completion_unknown`, perform no automatic retry and do not release the
    lease as successful.

Changing any repository, Project, item, operation scope, policy commit, producer
release, snapshot identity, plan identifier, plan digest, ordered operation-set
digest, capability digest, provider digest, environment, workflow, approval
issuer, approval subject or principal, approval issued-at, approval expiry,
approval nonce, nonce `scope_digest`, component idempotency key, Coordination
transcript epoch, effect-specific primitives restore epoch, lease resource or
holder, fencing token or lease generation, lease expiry or freshness bound,
verifier or postcondition invalidates the complete binding. Every such change,
including any source-field change that derives a new nonce scope, requires a
fresh plan and fresh approval before invocation. A primitives restore increments
its epoch and thereby invalidates every prior nonce, lease and capability even
when the relay transcript epoch is unchanged. Nonce replay, scope substitution,
replacement or expiry and lease contention, loss, renewal, generation change,
expiry, replacement or restore-epoch change can never be repaired under the
existing plan or approval.

Coordination stores enforce replay and concurrency only. A nonce result, lease,
fencing token, receipt, event, audit entry or successful teardown never grants
approval or protected-operation authority.

No nonce, lease capability, fencing token, plan, approval, credential,
idempotency key, verifier or audit receipt may cross from one effect to the
other. Teardown may remove the complete ephemeral state only after verified
evidence is frozen. It never selectively deletes terminal nonce or lease
entries to make reuse appear safe, and no later run reuses their account or
epoch.

## Public artifact boundary

Public evidence may contain only:

- immutable source, tree, artifact, SBOM and provenance digests;
- exact profile, schema, contract and conformance-corpus versions;
- logical component and effect labels;
- canonical run-manifest, compatibility-matrix and operation-set digests;
- relay receipt-chain, replay-projection and audit-checkpoint verification
  outcomes and digests;
- closed nonce scope-binding, call-count, outcome, lease, denial, verification
  and completion classes, including proof that a changed scope caused no second
  consume call or `consumed` outcome;
- bounded resource and cleanup outcomes;
- final teardown state and teardown-receipt digest;
- known limitations and residual-risk decisions.

Controlled, non-public operator evidence may contain the exact transient
container/runtime identities, private addresses, paths, port assignments,
provider request references and detailed incident diagnostics needed for
cleanup. It remains outside the repository and suite evidence index.

The following are forbidden from public artifacts, repository files, logs,
metrics, command arguments, environment variables and unrestricted
transcripts:

- tokens, proofs, private keys, NATS credentials, capability keys and lease
  capabilities;
- raw nonce `scope_digest` and `value_digest` inputs;
- approval envelopes, OIDC assertions and provider credentials;
- provider request/response bodies and private observations;
- raw event transcripts, event payload content and credential-bearing URLs;
- private infrastructure, host, account, namespace and filesystem identities;
- arbitrary provider errors or timestamps that disclose private operations.

Public evidence is structurally produced from closed values. Redaction after
capturing unrestricted output is not an accepted evidence path.

## Teardown lifecycle

Whole-sandbox teardown is a distinct ephemeral-profile operation. It is not an
RFC-0023 transcript redaction/deletion implementation, not a Projects restore
and not authorization to destroy any external target.

The run manifest selects one positive lifetime no greater than four hours.
Admission closes when the lifetime expires or any mandatory dependency becomes
unready. Teardown advances monotonically:

```text
requested
  -> admission_closed
  -> evidence_frozen
  -> credentials_revoked
  -> processes_stopped
  -> storage_removed
  -> absence_verified
  -> completed
```

The controller:

1. blocks new relay and primitives admission;
2. waits only for the already bounded in-flight operation deadline;
3. records verified final replay, receipt, audit, nonce/lease and process state;
4. emits closed public evidence before removing authoritative sandbox storage;
5. revokes or destroys every run-scoped client, workload, TLS, receipt-signing,
   capability and broker credential;
6. stops processes before removing networks and volumes;
7. verifies declared containers, networks, volumes, runtime files and
   credentials are absent;
8. emits one canonical teardown receipt containing only manifest/evidence
   digests, closed step outcomes and final state.

A failed or ambiguous step produces `teardown_incomplete`, quarantines the
remaining test-owned resources and requires accountable inspection. It never
reports success from process exit alone, retries an external effect, invents
missing evidence or broadens deletion. Cleanup of test-owned runtime resources
may be retried only against the same manifest and exact resource identities.

External synthetic GitHub state remains under Projects and MCP restore
authority. Any mutation needed to restore that state requires its own fresh
plan, approval, nonce, lease and evidence. Coordination teardown cannot perform
or imply it.

Because the profile destroys the complete ephemeral adapter state, it makes no
JetStream per-transcript lifecycle or restore claim. It cannot be used where
retained relay service, adopter data, backup restoration or RFC-0023 lifecycle
semantics are required.

## Failure semantics

The profile fails closed before provider invocation on:

- artifact, manifest, profile, policy, trust or configuration mismatch;
- bootstrap, custody, DPoP, authentication or authorization failure;
- receipt, audit, replay, cursor, epoch or projection verification failure;
- nonce replay, nonce scope mismatch or substitution, lease contention/loss,
  stale fence or primitives ambiguity;
- unavailable mandatory audit, signer, JetStream account or teardown evidence;
- cross-effect binding, binding digest, credential, account, key, nonce, lease,
  plan, approval, component idempotency key or verifier reuse;
- sandbox lifetime expiry or resource-bound exhaustion.

Failures have closed, bounded classes and no provider text. There is no hidden
retry, polling, credential switching, fallback adapter or automatic restart.
Unknown effect completion always remains distinct from proven failure without
effect and proven verified completion.

## Threats and controls

| Threat | Required control | Residual risk |
| --- | --- | --- |
| Coordination delivery treated as approval | component authority matrix and independent effect validation immediately before invocation | consumer implementation defect |
| Effect A authority reused by Effect B | distinct complete bindings and effect authority artifacts plus separate domains, services, accounts, credentials, buckets, epochs, verifiers and audit chains | compromised sandbox host can observe both |
| approved nonce value replayed under a different valid scope | domain-separated scope derivation, plan/approval binding and exact pre-call equality with zero changed-scope service calls | compromised protected consumer identity can still submit arbitrary RFC-0015 requests |
| insecure preview identity escapes into a normal executable | conformance-only construction, fresh per-run roots, isolated network and no compiled/default credential | source or build compromise |
| receipt or replay substitution | canonical byte, signature, binding, sequence and projection verification in each isolated client | run-scoped signer compromise |
| public evidence leaks secrets or topology | closed public schemas produced directly from safe values | controlled operator record still contains sensitive detail |
| teardown erases ambiguity | evidence freeze before removal and `teardown_incomplete` quarantine | host compromise can defeat absence verification |
| container/runtime confused deputy | no runtime socket, host source mount, ambient credentials or unrestricted writable host path | container runtime and host remain one failure domain |
| ephemeral storage misrepresented as retention lifecycle | whole-sandbox-only claim and explicit exclusion of JetStream lifecycle/restore | no retained-service recovery evidence |
| expired credential or lease silently renewed | fixed lifetimes, no implicit renew/retry and fresh authority for any later attempt | availability loss |
| broker topology becomes public contract | adapter-owned accounts, subjects, consumers and revisions | operator still administers all accounts |

The profile is logical isolation on one test host. It is not hardened
multi-tenancy. Host, container-runtime, preview-authority and operator
compromise remain accepted only for this bounded synthetic qualification and
cannot be inherited by production.

## Deterministic qualification required after acceptance

A later implementation is not reviewable without deterministic evidence for:

- exact manifest parsing and immutable artifact binding;
- network, account, credential, filesystem and process isolation;
- reference-versus-JetStream canonical protocol parity;
- independent client bootstrap, custody and receipt/replay verification;
- two-process reconnect to the same final projection digest;
- separate Effect A/B nonce, lease, budget, epoch and audit state;
- allowed shared repository/Project compatibility scope with different targets
  and/or disjoint ordered operation sets;
- cross-effect binding, digest, precondition snapshot, credential, nonce, lease,
  capability, fence, plan, approval, idempotency and verifier reuse rejection;
- same approved nonce value with a changed structurally valid scope denied before
  a second consume call, with one terminal `consumed` record only;
- zero provider calls for every required pre-effect denial;
- duplicate, reorder, reconnect, contention, lease loss, audit outage and
  unknown-completion outcomes;
- public evidence schema allowlists and forbidden-data scans;
- sandbox expiry and every teardown transition, crash and ambiguity;
- absence verification for exact test-owned containers, networks, volumes,
  runtime files and credentials;
- unchanged accepted relay, primitives, client and RFC-0022 conformance suites.

Tests use synthetic data and disposable local resources only. Network access is
disabled except among test-owned sandbox processes. No test may contact GitHub,
a registry, a cloud provider, an adopter resource or an operator path.

## Compatibility and sequencing

This profile changes no accepted event, receipt, HTTP/SSE, primitives or
capability wire bytes. It composes existing neutral ports behind a new profile
and adds only profile-specific manifest, evidence and teardown contracts.
RFC-0022 remains a separate private staging profile and supplies no credential
or deployment authority to this profile.

The acceptance and delivery sequence is:

1. merge the Proposed record and its threat-model/navigation delta in #196 at
   `b89dab83dac6fae19ba30e056ceb607e9854b510`;
2. record the project owner's explicit acceptance in #195;
3. merge this governance-only follow-up changing status and recording the exact
   acceptance;
4. only then open one execution-forbidden implementation issue for closed
   schemas, component-local assembly and hermetic tests;
5. return for independent component contract and test-readiness review;
6. request separate cross-suite authorization before any external effect,
   infrastructure, credential materialization, artifact publication or live
   traffic.

This accepted record completes the architecture gate through step 3. It creates
no implementation issue and performs no implementation or execution. Any later
step remains separately reviewed and subject to the prohibitions above.

## Alternatives rejected

### Implement from accepted RFC-0006 and RFC-0022

Rejected because RFC-0006 is an adapter contract and RFC-0022 is a one-identity
primitives staging profile. Neither authorizes a distributed relay process,
preview bootstrap, two effect domains or whole-sandbox teardown.

### Reuse one primitives identity and lease domain

Rejected because it would make shared policy, credential and storage state an
authority bridge between independently approved effects.

### Use direct NATS clients in Projects or MCP

Rejected because it exposes broker credentials and topology, duplicates
ambiguity/CAS behavior and bypasses the accepted client-neutral primitives API.

### Use fakes or allow-all providers in a runnable preview

Rejected because a network-reachable insecure mode would look operational while
discarding identity, policy, audit and receipt boundaries.

### Treat container deletion as sufficient teardown evidence

Rejected because process exit or deletion does not prove credential revocation,
evidence capture, storage absence or external effect state.

### Implement JetStream transcript lifecycle in this increment

Rejected because RFC-0023 explicitly excludes it and the ephemeral preview needs
only a bounded whole-sandbox claim. Retained distributed lifecycle requires a
separate RFC.

## Unresolved implementation choices

After acceptance, the implementation issue must select exact container tooling,
non-secret manifest syntax, per-run preview authority implementation and public
evidence schemas. Those choices may not change the ownership, isolation,
authority, failure, teardown or public-artifact boundaries fixed here.

Acceptance does not resolve those choices or authorize them outside the
separately reviewed, execution-forbidden implementation boundary above.
