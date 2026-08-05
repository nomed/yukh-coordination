# RFC-0022 private staging operator packet

- Status: complete review candidate; provisioning forbidden
- Prepared: 2026-08-04
- Reconciled: 2026-08-05
- Governing RFC: RFC-0022
- Governing issue: #136
- Reconciliation issues: #158, #159, #163
- Deployment plan: `private-primitives-staging-deployment-plan.md`

This is the public, redacted review half of the RFC-0022 step-5 operator
packet. It binds the immutable implementation and defines every outcome that
must be supplied before provisioning or explicitly deferred to its approved
step before the project owner can decide whether to authorize provisioning.
`PENDING` is a stop condition, never an approval or a usable default. A closed
deferred state records ordering only and grants no authority.

The corresponding private operator record must remain outside GitHub and the
repository. It may contain the exact endpoint, host and account identities,
named role holders, file paths and secret-delivery coordinates. It must never
copy credentials, private keys, descriptor numbers or secret bytes into this
public packet.

## Immutable candidate

| Field | Required value | Status |
|---|---|---|
| repository | `nomed/yukh-coordination` | VERIFIED |
| source commit | `d122f31ce6a74dcec97dfcf8095a4447e23ee593` | VERIFIED |
| Git tree | `a59ba3f7ad6018d96f7329710eb593766acda676` | VERIFIED |
| service profile | `yukh-coordination/private-primitives-staging-v1` | VERIFIED |
| bootstrap profile | `yukh-coordination/private-primitives-staging-bootstrap-v1` | VERIFIED |
| hermetic qualification | run `30851387901`, job `91811981779` | VERIFIED |
| MCP consumer commit | `e303b3671bf9b4c5202ae147b882ab763964d5ed` | VERIFIED |
| build toolchain | Go `1.26.5`, Linux AMD64 archive SHA-256 `5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053` | LOCALLY VERIFIED |
| service artifact SHA-256 | `00a9aacbb6c308d4a168cc087c2c396680edab55bb682458872056abce10f000` | INDEPENDENTLY REPRODUCED |
| bootstrap artifact SHA-256 | `edcdc8d99b26799795c3d5d7551b636d5009933e81683e512676e170852a55df` | INDEPENDENTLY REPRODUCED |
| descriptor launcher SHA-256 | `08d7dd79b9cc8afe68f9a2ccc367771157f6c6ee1856a7571dbe39f8e9a4f821` | INDEPENDENTLY REPRODUCED |
| superseding OCI manifest SHA-256 | `27ee06d3cc2a0b804424625e2570e3018b22bdd9b0dba7c28cd54e3b05d6ce7b` | INDEPENDENTLY REPRODUCED |
| superseding OCI config SHA-256 | `76f3d6db4b35ef6fe66b6f0b61627428f1f0d8327d4d52ee23032f3d30df9db5` | INDEPENDENTLY REPRODUCED |
| superseding OCI layer SHA-256 | `bed142fd3b1e8ce5f248de1d0f7068a9c837bfc563ab8d9a86fcb365186f2848` | INDEPENDENTLY REPRODUCED |
| superseding OCI SBOM SHA-256 | `2c6d1bc52e47fcecb0d60342719819e6fc99e486a6d398086a3bfbba81cbea13`; deterministic SPDX 2.3 over exactly three executables | INDEPENDENTLY REPRODUCED |
| immutable registry reference | digest-qualified reference with provider-observed manifest digest | `ghcr.io/nomed/yukh-coordination-private-primitives@sha256:27ee06d3cc2a0b804424625e2570e3018b22bdd9b0dba7c28cd54e3b05d6ce7b`; PROVIDER-OBSERVED PASS |

The executable and OCI digests were independently reproduced from the exact
delivery commit `83411ebf6b3a86b55ec527dfd40908a402e07c1a`, which embeds the
immutable source commit above. The two artifact digests came from two
byte-identical builds at the exact
source commit with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, an empty Go
build ID and the reviewed embedded revision. A later commit, mutable tag,
unrecorded compiler/toolchain or non-identical rebuild rejects the packet.
The separately authorized registry operation published exactly one private
package version. GHCR reported OCI image-manifest media type, size `402` and
the exact manifest digest above. The package remains private and owner-only;
no repository Actions access was granted. The owner accepted the bounded
first-publication residual risk that the existing operational PAT had broader
scopes than the planned one-shot package-write-only publisher. Its temporary
ORAS login state, toolchain, OCI layout and worktree were destroyed after
verification. The digest-qualified reference, never its publication tag, is
the only admissible target pull identity.

The OCI values recorded by issue #141 are historical and not deployable after
the descriptor launcher is introduced. Only the superseding digest set above
may enter the private Kubernetes runbook.

## Accountable roles

The private operator record must map one accountable human to each role below.
This public half records only separation outcomes; it never publishes names.

| Role | Required custody | Closed outcome |
|---|---|---|
| project owner / residual-risk acceptor | step-5 and step-7 decisions | PASS — privately identified |
| deployment operator | reviewed runbook only | PASS — project owner |
| security reviewer | identities, permissions, digests, limits and rollback | PASS — project owner |
| credential custodian | ephemeral workload and NATS material | PASS — project owner |
| MCP consumer operator | exact trust and descriptor-delivered consumer material | PASS — project owner |
| evidence reviewer | startup, audit and teardown receipts | PASS — project owner |
| incompatible-role conflicts | explicit, reviewed and accepted | PASS — owner explicitly accepts bounded first-staging consolidation |

An outcome is one of `PASS` or `REJECT`. A role holder may perform multiple
roles only when the private change record identifies the combination and the
security reviewer records `PASS` for that conflict.

## Redacted identity and policy evidence

Every digest is lowercase SHA-256 hexadecimal over a canonical, reviewer-owned
input. Digests are evidence references, not substitutes for private review.

| Evidence | Required public shape | Status |
|---|---|---|
| private-listener identity digest | 64 lowercase hexadecimal characters | `445e7758bdcff2ab94c01776dc6918914d9ccb4c4457425d758216611a017133`; LEAF ROTATION PASS |
| MCP trust-bundle digest | 64 lowercase hexadecimal characters | `ac9560e118851b63b7b40678fd9c3afe09fd35b13198946b7f038cc30a8a0115`; CEREMONY A PASS |
| canonical registration-template digest | 64 lowercase hexadecimal characters | `2b84604fc0c3233568c9bffe5d4af73387d8768d06fdc1a8d1441aa8e2291b82`; CEREMONY A PASS |
| signed-registration digest | 64 lowercase hexadecimal characters | DEFERRED_TO_APPROVED_STEP_5 per RFC-0024 |
| offline policy key ID | closed non-secret identifier | `yukh-rfc0024-policy-v1`; public-key SHA-256 `73104325bbf899f2f7f59c8d4e24ab14cf35b577cf87052265d4e0742e729921`; CEREMONY A PASS |
| five-action policy digest | 64 lowercase hexadecimal characters | `cb6cda8e3cf28d1aff9d23701974b7c5cadcca253c1c7adbc227d6988ed16732`; CEREMONY A PASS |
| NATS bootstrap credential-policy digest | 64 lowercase hexadecimal characters | `2060876139cf8e068b0ecfd7668a2fff91ca4ab929df99f94639a906fa47fe59`; CEREMONY A PASS |
| NATS runtime credential-policy digest | 64 lowercase hexadecimal characters | `81851f8a96eb8a79ca72cb12dbc382e164eece3dc71cfc8c348bd54ad88601a1`; CEREMONY A PASS |
| exact-action review | five RFC-0022 actions and no wildcard | PASS |
| endpoint/trust match review | closed `PASS` or `REJECT` | PASS |
| encrypted-custody and plaintext-destruction review | closed `PASS` or `REJECT` | PASS; redacted receipt SHA-256 `972bb20f1ae778668c3e641cdf131497d4cf881d466597a115d72a394eb9f1bd` |
| root and policy validity bound | absolute UTC timestamp | `2026-09-04T08:01:13Z` |
| server-leaf validity bound | absolute UTC timestamp | `2026-08-06T11:05:05Z`; LEAF ROTATION PASS; ROTATE AGAIN IF STEP 5 CANNOT COMPLETE SAFELY BEFORE EXPIRY |

The private review must prove that the NATS policy reaches only the nonce,
lease and capability-budget KV buckets and only the JetStream operations
needed by the bootstrap or runtime phase. Bootstrap and runtime credentials
are distinct and non-overlapping.

Accepted RFC-0024 resolves the signed-registration ordering. Before step 5 the
field remains `DEFERRED_TO_APPROVED_STEP_5` and the packet instead binds the
canonical registration-template digest. The actual signed-registration digest
is mandatory step-6 evidence after the <=15-minute token/DPoP inputs are
created during an approved step 5.

## Closed limits and epoch

No field has an operational default. The operator records each positive
integer in the private configuration and copies only the reviewed non-secret
value here.

| Field | Unit / bound | Value |
|---|---|---|
| NATS replicas | positive integer accepted by the candidate | `1` |
| NATS retention | milliseconds; greater than replay-safety window | `3600000` |
| replay-safety window | milliseconds | `300000` |
| capability limit | positive integer | `8` |
| capability pending timeout | milliseconds | `500` |
| NATS connection timeout | milliseconds | `1000` |
| NATS request timeout | milliseconds | `1000` |
| maximum lease lifetime | milliseconds | `60000` |
| positive restore epoch | integer greater than zero | `1`; reject if any prior state is discovered |
| service/three-bucket epoch agreement | closed `PASS` or `REJECT` | DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |

Any mismatch, zero value, rollback, expired evidence or value outside the
candidate's closed configuration rejects the packet.

## Private Kubernetes target assessment

The target and namespace identifiers remain only in the private operator
record. Read-only and server-side dry-run inspection recorded these closed
public outcomes without creating an object:

| Review | Outcome |
|---|---|
| unique private Kubernetes context and dedicated absent namespace | PASS |
| Linux AMD64 node profile | PASS |
| one default storage class | PASS |
| namespace server-side dry run | PASS |
| namespaced service account/RBAC, StatefulSet, Service and ConfigMap authority | PASS |
| Secret, NetworkPolicy and PVC authority | PASS |
| current namespace resources | ABSENT |

These outcomes prove only that a packet can be prepared. They do not authorize
namespace creation or establish runtime readiness.

## Filesystem, supervisor and lifecycle outcomes

| Review | Required outcome | Status |
|---|---|---|
| TLS certificate and key ownership/mode | regular, absolute, non-symlink, service cannot write | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| signed registration ownership/mode | supervisor-owned mode `0440` regular file | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| replay database parent ownership/mode | service-owned private storage | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| audit database parent ownership/mode | service-owned private storage | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| closed configuration ownership/mode | absolute, non-secret, immutable to service | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| descriptor purpose map | NATS runtime, capability keyring, token, DPoP key only; no numbers | PASS — compiled closed launcher |
| public listener host block | effective before process start | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| loopback operations listener | exact and non-routable | PLAN PASS; DEFERRED_TO_APPROVED_STEP_5_VERIFY_STEP_6 |
| rollback procedure identifier | reviewed non-secret identifier | `yukh-rfc0022-k8s-rollback-v1` |
| teardown procedure identifier | reviewed non-secret identifier | `yukh-rfc0022-k8s-teardown-v1` |
| audit-chain verification procedure | reviewed non-secret identifier | `yukh-rfc0022-audit-verify-v1` |

## Proposed synthetic window

The proposal may be prepared now but does not authorize RFC-0022 step 7.

| Field | Required value | Status |
|---|---|---|
| operation set | one nonce consume followed by acquire, inspect, renew, release and terminal inspect on synthetic bindings | PREDECLARED |
| provider/protected-target exclusion | closed `PASS` | PASS |
| retry policy | exactly no automatic retry | PASS |
| maximum expiry | absolute UTC timestamp, no more than credential lifetime | DEFERRED_TO_APPROVED_STEP_5; NOT_AUTHORIZED_FOR_TRAFFIC |
| qualification result | `NOT_RUN` before step 7 | NOT_RUN |

## Review decision

The packet may request step-5 approval only after every pre-step-5 `PENDING`
cell is replaced by a valid value or `PASS`. Closed deferred states are not
missing evidence and do not authorize their operation: they identify evidence
that can be created only during an approved step 5 and must be verified during
step 6. The security reviewer records one of these closed decisions:

- `REJECT`: one or more closed rejection reasons, with no provisioning;
- `REQUEST_STEP_5_APPROVAL`: complete packet presented to the project owner.

Current decision: `READY_TO_REQUEST_STEP_5_APPROVAL_TIME_CRITICAL`.

No pre-step-5 packet field remains pending. The selected rotated server leaf
expires at `2026-08-06T11:05:05Z`; if review and a safe step-5/step-6 interval cannot
complete before then, the leaf must be rotated through a separately authorized
ceremony and rebound before any step-5 approval request. Readiness to request
approval is not an approval request and grants no step-5 authority.

## Authorization boundary

This preparation candidate authorizes no infrastructure access or mutation.
It does not authorize artifact installation, bucket bootstrap, certificate or
credential generation, listener start or exposure, MCP configuration, network
traffic, provider execution, protected mutation, deployment or production use.
Only a later explicit owner approval of a complete packet can authorize
RFC-0022 step 5. Step 7 always requires a second independent approval after
the no-traffic step-6 review.
