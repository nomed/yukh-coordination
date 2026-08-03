# RFC-0022 private primitives staging implementation record

- Status: immutable implementation candidate
- Recorded: 2026-08-03
- Governing RFC: RFC-0022
- Governing issue: #90
- Publication issue: #110

## Immutable identity

The reviewed implementation candidate is exactly:

| Field | Value |
|---|---|
| Repository | `nomed/yukh-coordination` |
| Commit | `1af3ddb61f48539b7b2d426fb1d169db0b3cef21` |
| Git tree | `507a2358fdb17bc48b31e9af68f8d18296754bd8` |
| Profile | `yukh-coordination/private-primitives-staging-v1` |
| Qualification check | GitHub Actions run `30844534198`, job `91789486897`, success at 2026-08-03T19:10:16Z |

Commit and tree are the complete content identity. A later commit, rebuilt
archive, branch name or mutable tag is not this candidate. Deployment evidence
must record both values before installation and again from the installed source
or artifact provenance. This record does not designate a binary artifact:
none is published by the repository at this point.

## Reviewed delivery chain

| Boundary | Pull request | Squash commit |
|---|---:|---|
| Accepted private staging profile | #92 | `b454574f797acb98fb58e68f48a597afcfce8795` |
| Configuration, registration, DPoP and replay | #96 | `148dea7619128039b46ff6da4c276e862cc01249` |
| Direct TLS and operations runtime | #100 | `98841713ebd9cdd61e1047f6aa03d818c49679ea` |
| Mandatory audit gate | #103 | `b18942e42e3642bb269473d9bf85f6a3ee9ac8a8` |
| Capability-key descriptor custody | #106 | `90b0909111b70baabf41c5663769d9b1b29c1b91` |
| JetStream stores and restore epoch | #109 | `1af3ddb61f48539b7b2d426fb1d169db0b3cef21` |

The final commit contains all earlier boundaries. The chain is listed for
review traceability, not as a set of independently deployable artifacts.

## Qualification claim

At the recorded tree, the repository workflow installs its pinned disposable
NATS server and runs the complete Go suite with the race detector, followed by
the dependency-free Node qualification. The successful check covers generated
TLS roots and workload material, descriptor custody, replay and audit restart,
exact JetStream bucket configuration and epoch fencing, readiness loss,
shutdown and negative ambiguity cases.

This is hermetic implementation evidence only. It does not prove a packaged
executable, host hardening, real private-network routing, provisioned bucket,
live credential, exposed listener or MCP traffic.

## Known delivery gaps

The immutable candidate contains no `package main` executable entrypoint and
publishes no binary or container artifact. Normal staging composition also
forces JetStream bootstrap off, while RFC-0022 requires bucket creation to be a
separately reviewed accountable operation. Therefore the candidate is not yet
installable and provisioning approval must not be requested solely on this
record.

The next implementation increments must add, without changing the RFC-0015
wire contract:

1. a closed executable assembly that reads the one absolute non-secret config
   path, receives explicit inherited descriptors and owns bounded shutdown;
2. a separate, one-shot bootstrap operation for the exact nonce, lease and
   capability-budget buckets, with narrower credentials and redacted evidence;
3. reproducible artifact provenance tied back to this record or to a new
   explicitly reviewed superseding implementation commit.

Any code change produces a new implementation commit and requires this record
to be superseded. It cannot be treated as a harmless deployment substitution.

## Authorization boundary

Publishing this record completes only the recording portion of RFC-0022 step
4. It grants no permission to provision, mint credentials or keys, expose a
listener, connect MCP, send traffic, execute a provider, mutate a protected
target or use the profile in production.
