# SESSION-2026-08-05-12: RFC-0022 PodIP-aware OCI rebinding

- Governing issue: #174
- Parent execution issue: #167
- Pull request: #179
- Status: review candidate

## Objective

Independently reproduce, publish and provider-verify the PodIP-aware RFC-0022
scratch OCI, then rebind the public operator packet without exercising Step 5.

## Work completed

- rebuilt twice from delivery commit
  `ce607210c8ae9bd71c4d4adfc1414112cb2fa008` using exact Go 1.26.5;
- confirmed byte-identical OCI layouts and the reviewed scratch path allowlist;
- published one new private GHCR version under immutable publication tag
  `staging-v1-podip-13b97c16c376`;
- pulled by digest and proved the provider-returned manifest, config and layer
  blobs byte-identical to the independently reproduced layout;
- confirmed package visibility `private`, owner `nomed`, repository link absent
  and the historical package version retained.

## Evidence and validation

| Artifact | SHA-256 |
|---|---|
| service executable | `598adbc49a727bffef773d97e724c915960e8404509e3b9d6941dd447040720c` |
| bootstrap executable | `73f59bec1ea4fd76baa6b3b637859e08fd88fe7ca0cb7530d59f85380214c923` |
| descriptor launcher | `f120742330e675d7b59e1e8e715fd3c4cefbedca8bbdc2add2ebb2f9192f35c7` |
| OCI manifest | `13b97c16c376d98767123bf78af5c16cb65ab09960b16fec122eb017317fefbe` |
| OCI config | `1ba350b044f511915bfc4076584d95494213aee63c441e103ac79eac148f223a` |
| OCI layer | `c273cf19b7bfed29ab6d1b775c5749ea947fd5a01a48c4fe95b1c8781bf755f4` |
| SPDX SBOM | `eede90b9eee7a5e98ef735abf3304657223fb197dc779c7a9d2363e9fe6ba064` |

Provider descriptor: OCI image manifest, size `402`, exact digest above.
Immutable pull identity:
`ghcr.io/nomed/yukh-coordination-private-primitives@sha256:13b97c16c376d98767123bf78af5c16cb65ab09960b16fec122eb017317fefbe`.

## Decisions discovered

The prior manifest remains useful rollback evidence but cannot run the exact
PodIP-aware configuration. Only the new digest-qualified identity is admissible
for the renewed Step-5 packet.

## Context impact

The implementation record, deployment plan, threat model and operator packet
now bind the PodIP-aware source, delivery, workflow and registry identities.

## Risks and unresolved work

The existing operational PAT has broader scope than a one-shot publisher; the
owner previously accepted that bounded residual risk. Temporary ORAS login
state was destroyed. No target pull, Kubernetes object, credential, listener,
Step 5, MCP request or traffic action occurred. The retained server leaf
expires at `2026-08-06T11:05:05Z`; the renewed Step-5 decision remains
time-critical and must require another rotation if the safe window is no
longer sufficient.
