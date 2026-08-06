# RFC-0022 private primitives staging implementation record

- Status: offline OCI preparation review candidate; provisioning forbidden
- Recorded: 2026-08-06
- Governing RFC: RFC-0022
- Governing issue: #90
- Reconciliation issues: #129, #169, #174, #182, #184

## Immutable identity

The reviewed implementation candidate is exactly:

| Field | Value |
|---|---|
| Repository | `nomed/yukh-coordination` |
| Exact executable source commit | `92678da9d1d866c50371a683845c4675bf45c055` |
| Exact executable source tree | `7633caa18d16d1a3c488cd28f78ac808876cc5a5` |
| Tooling/record delivery review candidate | PR #192 head commit, tree and candidate-record blob emitted by its required `Go` check; `REVIEW CANDIDATE`, not delivered |
| Immutable post-merge delivery commit/tree | `PENDING POST-MERGE RECORDING`; provisioning stop |
| Service profile | `yukh-coordination/private-primitives-staging-v1` |
| Bootstrap profile | `yukh-coordination/private-primitives-staging-bootstrap-v1` |
| Recorded-source qualification check | candidate-specific CI rebuild of the exact source commit; two isolated archives; Go 1.26.5 Linux AMD64; network namespace disabled |
| Checkout qualification check | separate CI qualification of checked-out/merge bytes; not evidence for the recorded source |

The executable source is the exact identity embedded in and used to construct
the recorded OCI bytes. It predates this PR and is not the commit that delivers
the revised tooling or records. PR #192 is the tooling/record delivery review
candidate. Its required check externally binds the exact PR head commit, tree
and `.github/records/private-primitives-oci-review-candidate.txt` blob for each
reviewed run, so a changed head necessarily creates a new review candidate.

The final immutable delivery identity cannot be stated inside the commit that
does not yet exist. After merge, the successful `main` check emits the merged
commit, tree and candidate-record blob. The owner records those values in issue
#184 and a later packet-reconciliation commit verifies ancestry and unchanged
record-blob identity. That later recording commit is evidence about the
delivery commit; it is not renamed as the delivery commit. Until this
non-circular post-merge recording is complete, the delivery identity is
`PENDING` and provisioning remains stopped.

This record supersedes the source and OCI bindings at
`25ec7901796208785ec25f20b5fc4c0d7bc05eba`,
`d122f31ce6a74dcec97dfcf8095a4447e23ee593` and
`1af3ddb61f48539b7b2d426fb1d169db0b3cef21`. They remain historical
evidence and are not deployable candidates.

## Reviewed delivery chain

| Boundary | Pull request | Squash commit |
|---|---:|---|
| Accepted private staging profile | #92 | `b454574f797acb98fb58e68f48a597afcfce8795` |
| Configuration, registration, DPoP and replay | #96 | `148dea7619128039b46ff6da4c276e862cc01249` |
| Direct TLS and operations runtime | #100 | `98841713ebd9cdd61e1047f6aa03d818c49679ea` |
| Mandatory audit gate | #103 | `b18942e42e3642bb269473d9bf85f6a3ee9ac8a8` |
| Capability-key descriptor custody | #106 | `90b0909111b70baabf41c5663769d9b1b29c1b91` |
| JetStream stores and restore epoch | #109 | `1af3ddb61f48539b7b2d426fb1d169db0b3cef21` |
| Closed staging service executable | #121 | `6c47920135ad29e36b7e591fc6f401f9eec2fa34` |
| Accountable three-bucket bootstrap executable | #127 | `d122f31ce6a74dcec97dfcf8095a4447e23ee593` |
| Kubernetes PodIP-aware descriptor launcher | #171 | `ce607210c8ae9bd71c4d4adfc1414112cb2fa008` |
| Non-root runtime-directory closure | #183 | `ee8d74d89fdc30f37d4d8e8c75c922a473c6d9c6` |
| JetStream state and secret boundary documentation | #189 | `92678da9d1d866c50371a683845c4675bf45c055` |

The final candidate contains every earlier implementation boundary. The chain
is traceability evidence, not a set of independently substitutable artifacts.

## Qualified executable boundaries

The service executable accepts exactly one absolute, non-secret closed config
path. It receives the NATS runtime credential and capability keyring only
through fixed inherited descriptors, composes the accepted TLS, registration,
replay, audit, capability, JetStream and RFC-0015 boundaries, never enables
bucket bootstrap, and owns bounded readiness and shutdown.

The separate one-shot bootstrap executable accepts its own absolute,
non-secret closed config and one narrower inherited NATS credential descriptor.
It can create missing or exactly verify only the nonce, lease and
capability-budget buckets. It has no listener, service runtime, update, delete,
purge, migration, repair or provider path. Success emits only the closed
revision/epoch/bucket-profile receipt; failure emits no private detail.

Both executables embed the candidate revision. The qualification script builds
each twice with `CGO_ENABLED=0`, trimmed paths, disabled VCS stamping and no
build ID, then requires byte equality and the exact embedded revision.

The static descriptor launcher adds one closed `service-kubernetes` mode that
materializes only the exact private PodIP bind before executing the unchanged
service boundary. It introduces no shell, proxy, init image, wildcard bind or
new secret purpose. It creates the exact private runtime child required by the
non-root Kubernetes mount contract and rejects unsafe ownership, mode, symlink
or pre-population states.

## Offline OCI preparation evidence

Repository-owned tooling archived exact commit
`92678da9d1d866c50371a683845c4675bf45c055` twice and built each archive under
Go 1.26.5 Linux AMD64 with networking disabled. The complete OCI layouts were
byte-identical. The layer path allowlist contained only the three reviewed
executables, fixed account files and empty directory structure; executable
bytes were independently hashed from the layer.

| Artifact | SHA-256 |
|---|---|
| service executable | `e6561075524e699b58b5c6fca3aa0dbae1a00e75e9750807167eb2da8f97d585` |
| bootstrap executable | `65a3d0b2f123180ca93c3ce5542b3b29010f29ce20589b929b6d499fdc7302d5` |
| descriptor launcher | `4eecf130db6431d6f89079ee6ec9a8273d8c8107ba47e6aabb1adc89f0e29d31` |
| OCI manifest | `aed277ad73266bcbef2e8e88fc9fd4fc99bf775b9e627abed5a0c36bdd3900d7` |
| OCI config | `2e4f4c2575efbb71464c6b6527df4a49745b24ddb0c1958380be7d8061fd9a71` |
| OCI layer | `df686b0e685fc23a72d9c077a776a7b0d56f4ecc3977bdd1ca5af3984539555c` |
| SPDX SBOM | `72fbe3c9184e0244aaee06ba1e0b90a4fc75525c16f2b03fee4663b50911439f` |

These exact values and the source tree, two-build result, complete-layout byte
identity, executable allowlist and cleanup result are recorded in
`.github/records/private-primitives-oci-review-candidate.txt`. The
candidate-specific verifier checks out that exact source from the local Git
object database, independently rebuilds it twice, validates every manifest,
config, layer, SBOM and executable digest, and requires an exact record match.
The builder normalizes the non-special tar device fields and header checksums
to the recorded GNU tar 1.34 encoding so a runner's GNU tar 1.35 empty-field
change cannot silently alter the layer. Mismatch and stale source/tree failure
tests run before that verification.

Both source archives, OCI layouts and build workspaces were removed and their
absence verified before the preparation command returned success. These are
local review-candidate identities only. No registry authentication,
publication, push, pull or provider comparison occurred.

## Qualification claim

The repository workflow separately qualifies its ordinary checkout/PR merge
bytes; that result is not substituted for the recorded-source result. It also
installs pinned disposable NATS, runs the complete Go suite with the race
detector, exercises bootstrap
create-then-verify against exactly three buckets, qualifies TLS, registration,
descriptor custody, replay, audit, readiness, shutdown and negative ambiguity
cases, proves reproducible executable builds, and runs the dependency-free
Node qualification offline. Both OCI paths run in a network-disabled namespace.
The candidate path performs no registry/provider operation and receives no
credential.

This is hermetic implementation evidence. It does not prove a hardened host,
private routing, concrete trust or policy digests, a provisioned real bucket,
live credential, exposed listener, MCP request or production suitability.

## Remaining delivery gate

The executable and bootstrap implementation gaps identified by #110 are
closed. Provisioning nevertheless remains forbidden until separately authorized
private publication and provider pull comparison bind the exact reproduced
bytes to an immutable registry identity and the reviewed operator packet binds
that identity together with
redacted trust/policy/credential-policy evidence, fixed limits, positive epoch,
filesystem outcomes, rollback identifiers and bounded synthetic-window expiry
required by the deployment plan.

`nomed/yukh-mcp#50` may use this immutable contract only to continue its
disabled-by-default adapter implementation and hermetic qualification. It gains
no endpoint, trust material, credential, provisioning or live-request authority
from this record.

## Authorization boundary

Publishing this record completes only RFC-0022 step 4. It grants no permission
to provision infrastructure, mint credentials or keys, run the bootstrap
against real NATS, expose a listener, connect MCP to a live endpoint, send
traffic, execute a provider, mutate a protected target or use the profile in
production.
