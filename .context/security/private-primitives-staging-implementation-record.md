# RFC-0022 private primitives staging implementation record

- Status: superseding immutable implementation candidate
- Recorded: 2026-08-05
- Governing RFC: RFC-0022
- Governing issue: #90
- Reconciliation issues: #129, #169, #174

## Immutable identity

The reviewed implementation candidate is exactly:

| Field | Value |
|---|---|
| Repository | `nomed/yukh-coordination` |
| Source candidate commit | `25ec7901796208785ec25f20b5fc4c0d7bc05eba` |
| Source candidate tree | `43b2deab95a62dcc3d48a83d9fc8a93e0c8aa4a0` |
| Delivery commit | `ce607210c8ae9bd71c4d4adfc1414112cb2fa008` |
| Delivery tree | `23f90cf916e0f1885576f500f7a64c28985d7a33` |
| Service profile | `yukh-coordination/private-primitives-staging-v1` |
| Bootstrap profile | `yukh-coordination/private-primitives-staging-bootstrap-v1` |
| Qualification check | post-merge GitHub Actions run `31018394591`, job `92348429268`, success at 2026-08-05T15:05:32Z |

The source candidate and tree are the exact embedded executable identity; the
delivery commit and tree are the reviewed merge that binds its build and
qualification records. A later commit, rebuilt archive, branch or mutable tag
is not this candidate. The operator packet binds reproducibly built artifacts
and their private registry identity to these exact source and delivery values.

This record supersedes `d122f31ce6a74dcec97dfcf8095a4447e23ee593`
and the earlier `1af3ddb61f48539b7b2d426fb1d169db0b3cef21`. Both remain
historical evidence and are not deployable candidates.

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
new secret purpose.

## Qualification claim

At the recorded tree, the repository workflow installs pinned disposable NATS,
runs the complete Go suite with the race detector, exercises bootstrap
create-then-verify against exactly three buckets, qualifies TLS, registration,
descriptor custody, replay, audit, readiness, shutdown and negative ambiguity
cases, proves reproducible executable builds, and runs the dependency-free
Node qualification offline.

This is hermetic implementation evidence. It does not prove a hardened host,
private routing, concrete trust or policy digests, a provisioned real bucket,
live credential, exposed listener, MCP request or production suitability.

## Remaining delivery gate

The executable and bootstrap implementation gaps identified by #110 are
closed. Provisioning nevertheless remains forbidden until a separately
reviewed operator packet supplies the exact reproducible artifact digests,
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
