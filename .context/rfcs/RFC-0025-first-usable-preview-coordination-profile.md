# RFC-0025: First usable preview Coordination profile

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-09
- Governing issue: #195
- Governing suite issue: `nomed/nomed.github.io#40`
- Governing suite architecture: accepted `nomed.github.io` RFC-0005 on `main`
  at `12d9215f10c4b7fb1762a5025367e3e81543800f` through PR #42
- Governing Coordination architecture: RFC-0002, RFC-0003, RFC-0006,
  RFC-0009 through RFC-0017, RFC-0019, RFC-0021 through RFC-0024

## Decision requested

Accept one explicitly non-production Coordination profile for the first usable
Yukh suite preview. The profile composes:

- the RFC-0006 JetStream relay command log;
- the accepted relay HTTP/SSE, bootstrap and signed-receipt boundaries;
- two isolated client sessions with independent credential custody;
- two effect-specific instances of the accepted nonce and fenced-lease service;
- mandatory audit, public evidence and deterministic verification boundaries;
  and
- one bounded whole-sandbox teardown lifecycle.

This proposal is required because no accepted Coordination record authorizes
that composition. RFC-0006 qualifies the distributed relay adapter but not a
distributed executable profile. RFC-0022 selects one private staging primitives
identity and no relay. RFC-0023 explicitly excludes JetStream lifecycle.
Accepted client records do not select a preview bootstrap authority or a
container lifecycle. Treating those records as implicit suite-preview authority
would cross security and component boundaries without review.

This record remains **Proposed**. Merging it in this state authorizes no
implementation or execution. The project owner must explicitly accept this RFC
in #195 and a follow-up accepted record before any implementation issue may
begin.

If accepted, this RFC authorizes only a separately reviewed, execution-forbidden
implementation and hermetic synthetic qualification. It does not authorize
infrastructure provisioning, OCI publication, credential creation outside a
test-owned ephemeral process, live traffic, GitHub mutation, provider
registration or execution, preview publication, production use or a
production-readiness claim.

## Profile identity and ownership

The proposed profile identifier is:

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

Credential generation and use belong only to a later hermetic test after this
RFC is accepted and implementation is separately approved. This proposal
creates no key, token, certificate, registration or credential.

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

Each effect has one complete canonical authority binding. It contains exactly:

- repository, Project, item and ordered operation scope;
- policy commit and immutable producer release;
- fresh precondition snapshot identity;
- plan identifier and canonical plan digest;
- ordered operation-set digest;
- capability-definition and provider-implementation digests where MCP applies;
- environment and protected-workflow identity;
- approval issuer, authenticated approval subject, issue time, expiry and unique
  approval nonce;
- component-scoped idempotency key;
- Coordination epoch and exact fenced-lease identity; and
- verifier identity and declared postconditions.

The fenced-lease identity canonically binds the effect-specific scope, holder
and Coordination epoch. Provider revisions and the returned fencing token remain
runtime evidence, not approval authority, but they must resolve to that exact
approved lease identity and be current immediately before invocation.

The two effects use distinct values for every authority-bearing field above.
Effect A cannot omit or reuse a binding because it invokes Projects directly.
Effect B cannot reuse an Effect A binding because its MCP capability adds
another admission boundary. A field that does not apply to Effect A is
canonically absent under the closed Effect A schema; it is never copied from
Effect B, set to a wildcard or ignored during comparison.

Each effect derives its nonce value, lease scope and lease holder digests from
that complete canonical binding using effect-specific domains:

```text
effect_a_nonce = SHA-256(
  "yukh-suite-preview:effect-a:nonce:v1\n" || canonical_effect_a_binding
)
effect_a_lease_scope = SHA-256(
  "yukh-suite-preview:effect-a:scope:v1\n" || canonical_effect_a_binding
)
effect_a_lease_holder = SHA-256(
  "yukh-suite-preview:effect-a:holder:v1\n" || canonical_effect_a_binding
)

effect_b_nonce = SHA-256(
  "yukh-suite-preview:effect-b:nonce:v1\n" || canonical_effect_b_binding
)
effect_b_lease_scope = SHA-256(
  "yukh-suite-preview:effect-b:scope:v1\n" || canonical_effect_b_binding
)
effect_b_lease_holder = SHA-256(
  "yukh-suite-preview:effect-b:holder:v1\n" || canonical_effect_b_binding
)
```

Even identical source bytes therefore produce different effect and purpose
digests. Conformance vectors must freeze both closed canonical binding schemas
and every derivation before a consumer can use the profile.

For each effect:

1. its own workload identity consumes the exact nonce derived from the complete
   approved binding;
2. replay, changed bytes or ambiguity stops before provider invocation;
3. it acquires the exact effect-specific lease identity derived from the same
   binding, with no implicit retry;
4. the protected consumer reconstructs the complete canonical binding from its
   authenticated plan, approval, snapshot, environment, nonce and lease inputs
   and requires byte-for-byte equality with the approved canonical binding;
5. it independently verifies current nonce consumption, lease validity and
   fencing token immediately before effect without treating any of them as
   authority outside the canonical binding;
6. provider invocation is forbidden unless every canonical field and derived
   value is exactly equal and current;
7. provider acknowledgement is not verification;
8. verified completion permits explicit release;
9. possible effect with lost or ambiguous response records
   `completion_unknown`, performs no automatic retry and does not release the
   lease as successful.

Any changed policy, release, repository, Project, item, operation scope,
snapshot, plan identifier, plan digest, ordered operation set, capability,
provider, environment, workflow, approval field, nonce, idempotency key,
Coordination epoch, lease identity, verifier or postcondition invalidates the
binding. The consumer must obtain a new plan and a new approval before acquiring
or invoking under the changed value. In particular, nonce replay, replacement
or expiry and lease contention, loss, expiry or replacement cannot be repaired
under the existing plan or approval.

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
- closed nonce, lease, denial, verification and completion classes;
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
- nonce replay, lease contention/loss, stale fence or primitives ambiguity;
- unavailable mandatory audit, signer, JetStream account or teardown evidence;
- cross-effect binding, credential, account, key, nonce or lease reuse;
- sandbox lifetime expiry or resource-bound exhaustion.

Failures have closed, bounded classes and no provider text. There is no hidden
retry, polling, credential switching, fallback adapter or automatic restart.
Unknown effect completion always remains distinct from proven failure without
effect and proven verified completion.

## Threats and controls

| Threat | Required control | Residual risk |
| --- | --- | --- |
| Coordination delivery treated as approval | component authority matrix and independent effect validation immediately before invocation | consumer implementation defect |
| Effect A authority reused by Effect B | separate canonical domains, services, accounts, credentials, buckets, epochs, verifiers and audit chains | compromised sandbox host can observe both |
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
- cross-effect credential, scope, nonce, lease, capability and fence rejection;
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
and adds only profile-specific manifest, evidence and teardown contracts after
acceptance. RFC-0022 remains a separate private staging profile and supplies no
credential or deployment authority to this proposal.

The sequence is:

1. merge this Proposed record and its threat-model/navigation delta;
2. obtain an explicit owner decision in #195;
3. if accepted, merge a follow-up record changing status and recording the
   exact acceptance;
4. only then open one execution-forbidden implementation issue for closed
   schemas, component-local assembly and hermetic tests;
5. return for independent component contract and test-readiness review;
6. request separate cross-suite authorization before any external effect,
   infrastructure, credential materialization, artifact publication or live
   traffic.

The exact current gate is step 2. No implementation may begin from a Proposed
record, an issue label, a suite RFC acceptance or a merged design-only pull
request.

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

No unresolved choice permits implementation while this RFC remains Proposed.
