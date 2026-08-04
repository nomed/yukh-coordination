# RFC-0022 private staging operator packet

- Status: preparation candidate; provisioning forbidden
- Prepared: 2026-08-04
- Governing RFC: RFC-0022
- Governing issue: #136
- Deployment plan: `private-primitives-staging-deployment-plan.md`

This is the public, redacted review half of the RFC-0022 step-5 operator
packet. It binds the immutable implementation and defines every outcome that
must be supplied before the project owner can decide whether to authorize
provisioning. `PENDING` is a stop condition, never an approval or a usable
default.

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
| service artifact SHA-256 | `00a9aacbb6c308d4a168cc087c2c396680edab55bb682458872056abce10f000` | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |
| bootstrap artifact SHA-256 | `edcdc8d99b26799795c3d5d7551b636d5009933e81683e512676e170852a55df` | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |
| OCI manifest SHA-256 | `f3ae988c7aab21a1492e4108d45a3bafdd1d25b9431378d3fab8ef0a11aa7636` | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |
| OCI config SHA-256 | `4be24611d67628889075d1782530d9b8822dda0ffc6396b157b14dc9e7f7872d` | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |
| OCI layer SHA-256 | `83be76c5dcfe0a613f380df70dcf772beae89546a7f607256287d013e51b8362` | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |
| OCI SBOM SHA-256 | `bd0a9fc0e7487acdb3755792a82a466d312decfabd86d83fb285e9b4a0334a88`; deterministic SPDX 2.3 over exactly two executables | LOCALLY REPRODUCED; INDEPENDENT REVIEW PENDING |

The two artifact digests must come from two byte-identical builds at the exact
source commit with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, an empty Go
build ID and the reviewed embedded revision. A later commit, mutable tag,
unrecorded compiler/toolchain or non-identical rebuild rejects the packet.
The recorded local build produced two byte-identical copies of each artifact;
an accountable reviewer must independently reproduce both digests before the
packet can request step-5 approval.

## Accountable roles

The private operator record must map one accountable human to each role below.
This public half records only separation outcomes; it never publishes names.

| Role | Required custody | Closed outcome |
|---|---|---|
| project owner / residual-risk acceptor | step-5 and step-7 decisions | PENDING |
| deployment operator | reviewed runbook only | PENDING |
| security reviewer | identities, permissions, digests, limits and rollback | PENDING |
| credential custodian | ephemeral workload and NATS material | PENDING |
| MCP consumer operator | exact trust and descriptor-delivered consumer material | PENDING |
| evidence reviewer | startup, audit and teardown receipts | PENDING |
| incompatible-role conflicts | explicit, reviewed and accepted | PENDING |

An outcome is one of `PASS` or `REJECT`. A role holder may perform multiple
roles only when the private change record identifies the combination and the
security reviewer records `PASS` for that conflict.

## Redacted identity and policy evidence

Every digest is lowercase SHA-256 hexadecimal over a canonical, reviewer-owned
input. Digests are evidence references, not substitutes for private review.

| Evidence | Required public shape | Status |
|---|---|---|
| private-listener identity digest | 64 lowercase hexadecimal characters | PENDING |
| MCP trust-bundle digest | 64 lowercase hexadecimal characters | PENDING |
| signed-registration digest | 64 lowercase hexadecimal characters | PENDING |
| offline policy key ID | closed non-secret identifier | PENDING |
| five-action policy digest | 64 lowercase hexadecimal characters | PENDING |
| NATS credential-policy digest | 64 lowercase hexadecimal characters | PENDING |
| exact-action review | five RFC-0022 actions and no wildcard | PENDING |
| endpoint/trust match review | closed `PASS` or `REJECT` | PENDING |

The private review must prove that the NATS policy reaches only the nonce,
lease and capability-budget KV buckets and only the JetStream operations
needed by the bootstrap or runtime phase. Bootstrap and runtime credentials
are distinct and non-overlapping.

## Closed limits and epoch

No field has an operational default. The operator records each positive
integer in the private configuration and copies only the reviewed non-secret
value here.

| Field | Unit / bound | Value |
|---|---|---|
| NATS replicas | positive integer accepted by the candidate | PENDING |
| NATS retention | milliseconds; greater than replay-safety window | PENDING |
| replay-safety window | milliseconds | PENDING |
| capability limit | positive integer | PENDING |
| capability pending timeout | milliseconds | PENDING |
| NATS connection timeout | milliseconds | PENDING |
| NATS request timeout | milliseconds | PENDING |
| maximum lease lifetime | milliseconds | PENDING |
| positive restore epoch | integer greater than zero | PENDING |
| service/three-bucket epoch agreement | closed `PASS` or `REJECT` | PENDING |

Any mismatch, zero value, rollback, expired evidence or value outside the
candidate's closed configuration rejects the packet.

## Filesystem, supervisor and lifecycle outcomes

| Review | Required outcome | Status |
|---|---|---|
| TLS certificate and key ownership/mode | regular, absolute, non-symlink, service cannot write | PENDING |
| signed registration ownership/mode | supervisor-owned mode `0440` regular file | PENDING |
| replay database parent ownership/mode | service-owned private storage | PENDING |
| audit database parent ownership/mode | service-owned private storage | PENDING |
| closed configuration ownership/mode | absolute, non-secret, immutable to service | PENDING |
| descriptor purpose map | NATS runtime, capability keyring, token, DPoP key only; no numbers | PENDING |
| public listener host block | effective before process start | PENDING |
| loopback operations listener | exact and non-routable | PENDING |
| rollback procedure identifier | reviewed non-secret identifier | PENDING |
| teardown procedure identifier | reviewed non-secret identifier | PENDING |
| audit-chain verification procedure | reviewed non-secret identifier | PENDING |

## Proposed synthetic window

The proposal may be prepared now but does not authorize RFC-0022 step 7.

| Field | Required value | Status |
|---|---|---|
| operation set | one predeclared synthetic nonce/lease lifecycle | PENDING |
| provider/protected-target exclusion | closed `PASS` | PENDING |
| retry policy | exactly no automatic retry | PENDING |
| maximum expiry | absolute UTC timestamp, no more than credential lifetime | PENDING |
| qualification result | `NOT_RUN` before step 7 | NOT_RUN |

## Review decision

The packet is complete only when every `PENDING` cell is replaced by a valid
value or `PASS`, both artifact digests are independently reproduced, and the
security reviewer records one of these closed decisions:

- `REJECT`: one or more closed rejection reasons, with no provisioning;
- `REQUEST_STEP_5_APPROVAL`: complete packet presented to the project owner.

Current decision: `REJECT_INCOMPLETE`.

## Authorization boundary

This preparation candidate authorizes no infrastructure access or mutation.
It does not authorize artifact installation, bucket bootstrap, certificate or
credential generation, listener start or exposure, MCP configuration, network
traffic, provider execution, protected mutation, deployment or production use.
Only a later explicit owner approval of a complete packet can authorize
RFC-0022 step 5. Step 7 always requires a second independent approval after
the no-traffic step-6 review.
