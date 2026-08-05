# RFC-0022 private staging redacted deployment plan

- Status: reconciled review candidate; execution forbidden
- Recorded: 2026-08-03
- Governing RFC: RFC-0022
- Governing issue: #90
- Reconciliation issues: #129, #169, #174
- Implementation record: `private-primitives-staging-implementation-record.md`

This public plan intentionally contains no endpoint, address, account,
credential, key, subject content, tenant, principal, host identifier or private
infrastructure detail. Concrete values belong in a separately controlled
operator record and only their approved digests or closed outcomes may enter
public evidence.

## Stop condition before provisioning approval

The immutable source candidate now contains both reproducibly qualified
executables and the separately reviewed accountable three-bucket bootstrap.
That closes the implementation prerequisites but does not itself authorize
provisioning. No infrastructure or credential work may begin until a concrete,
redacted operator packet binds reproducible artifact digests and every item
below to source candidate `25ec7901796208785ec25f20b5fc4c0d7bc05eba`,
tree `43b2deab95a62dcc3d48a83d9fc8a93e0c8aa4a0`, delivery commit
`ce607210c8ae9bd71c4d4adfc1414112cb2fa008` and tree
`23f90cf916e0f1885576f500f7a64c28985d7a33`, and the owner explicitly approves
that complete packet.

## Accountable roles

One named human may hold more than one role only if the private change record
makes that explicit:

- project owner and residual-risk acceptor: grants the step 5 and step 7
  approvals separately;
- deployment operator: prepares the host and executes only the reviewed runbook;
- security reviewer: verifies identities, permissions, digests, limits and
  rollback before each approval;
- credential custodian: creates and destroys the ephemeral workload and NATS
  credentials without placing plaintext in durable evidence;
- MCP consumer operator: receives only the RFC-0015 endpoint trust and
  descriptor-delivered consumer material after step 6 review;
- evidence reviewer: verifies redacted startup, audit and teardown receipts.

No role gains MCP approval, provider or protected-target authority from this
profile.

## Redacted topology

The profile uses one isolated Linux staging host and one active process. The
public primitives listener binds one exact private or loopback address and
terminates TLS 1.3 directly. The operations listener is loopback-only. Replay
and audit SQLite files reside on supervisor-controlled local storage.

The delivered composition permits only a literal loopback `nats://` server.
Therefore the disposable JetStream server and its three fixed buckets must be
co-located on the same isolated host. Remote NATS, TLS NATS, system trust,
service discovery, proxy discovery, clustering, automatic failover and a
second active primitives process are outside this candidate.

The future MCP consumer is outside the Coordination host. It receives only an
exact HTTPS base origin, an explicit private trust bundle, one short-lived
opaque token and its distinct ephemeral DPoP private key through the consumer's
descriptor boundary. It receives no NATS information or credential.

## Required pre-provisioning package

The operator must prepare one review packet containing only these redacted
fields:

- implementation commit, Git tree and reproducible artifact digest;
- closed executable and bootstrap operation versions;
- private-listener identity digest and trust-bundle digest;
- signed-registration digest, policy key ID and five-action policy digest;
- NATS credential policy digest proving access only to the three fixed KV
  buckets and required JetStream operations;
- exact replicas, retention, replay-safety, capability limit, pending timeout,
  connection timeout, request timeout and maximum lease lifetime;
- positive restore epoch and evidence that service plus all three buckets agree;
- filesystem ownership/mode outcomes for TLS, registration, replay and audit
  paths;
- supervisor descriptor map by purpose, never descriptor numbers or contents;
- rollback and teardown procedure identifiers;
- qualification result and expiry of the proposed synthetic window.

Any missing, mismatched, expired or non-redacted item stops the process.

## Step 5 — separately approved provisioning

Only after explicit owner approval of the complete packet may the deployment
operator:

1. prepare the isolated host and local storage without exposing listeners;
2. install the exact reviewed artifact and non-secret closed configuration;
3. run the separately reviewed one-shot bucket bootstrap with its narrower
   credential, then revoke and destroy that credential;
4. generate the private TLS identity, capability keyring, NATS runtime
   credential and signed public registration under their distinct custody
   boundaries;
5. generate one opaque workload token and one ephemeral P-256 DPoP key with a
   validity of at most fifteen minutes, but deliver neither to MCP yet;
6. start dependencies and the primitives process with the public listener
   blocked by host controls;
7. collect only closed readiness and audit evidence, then stop for review.

Provisioning approval does not authorize a network request.

## Step 6 — no-traffic review

The security reviewer verifies the implementation/artifact identity, exact
server certificate identity, trust and policy digests, five-action registration,
limits, epoch agreement, bucket configuration, audit-chain validity, readiness,
credential expiry, listener block and rollback feasibility. The reviewer
records closed pass/fail outcomes and no secret or private endpoint.

Failure tears down the workload credential and listener, removes readiness and
preserves audit plus JetStream terminal/fencing state. It never lowers the
epoch, deletes history or retries an ambiguous mutation.

## Step 7 — second owner approval

One live qualification window requires a new explicit approval after the
no-traffic packet is reviewed. The approval must bind the reviewed artifact
digest, trust/policy digests, restore epoch, synthetic operation list, maximum
window expiry and rollback identifier. Silence, an earlier implementation
approval or provisioning approval is not sufficient.

## Step 8 — bounded synthetic window

After the second approval, MCP may use only RFC-0015 bytes to perform the
predeclared synthetic nonce and lease lifecycle. No provider is invoked and no
protected target is named or mutated. There is no automatic retry; an ambiguous
result is reconciled only through the accepted inspect operation.

At window end the operator blocks the listener, revokes/removes the
registration, destroys the workload and NATS runtime credentials, closes the
consumer trust path, stops the process, verifies key zeroization and validates
the redacted audit chain. JetStream terminal/fencing state is preserved for
accountable inspection.

## Evidence retained publicly

Public evidence may contain commit/tree/artifact and policy/trust digests,
closed reason codes, exact non-secret numeric limits, restore epoch, timestamps,
audit/checkpoint references and teardown outcomes. It must not contain private
endpoints, host or account identities, descriptor numbers, credentials, keys,
proofs, capabilities, request/response bodies, scope/value/holder digests,
bucket contents or arbitrary provider errors.

## Rollback

Rollback first removes readiness and blocks the listener, then cancels bounded
requests, closes JetStream ownership, zeroes capability material and stops the
process. It revokes ephemeral credentials and removes consumer trust while
preserving audit and fencing evidence. Recovery requires a positive new epoch
when restore evidence demands it; rollback never reduces an epoch or erases
state to make a retry appear safe.

## Authorization boundary

Merging this reconciled plan does not authorize step 5. The next owner decision
may occur only after the complete candidate-bound operator packet exists and is
reviewed. Step 7 always remains a second independent approval.
