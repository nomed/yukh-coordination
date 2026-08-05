# SESSION-2026-08-05-05: RFC-0022 Kubernetes PodIP launcher

- Governing issue: #169
- Pull request: #171
- Status: implementation candidate

## Objective

Close the exact Kubernetes PodIP at launcher time without adding a shell,
sidecar, init image, proxy, wildcard bind or new infrastructure component.

## Work completed

- added the typed `${YUKH_POD_IP}:8443` configuration slot and a closed renderer
  that accepts only one canonical private non-loopback PodIP;
- added the fixed `service-kubernetes TEMPLATE PODIP OUTPUT NATS KEYRING`
  launcher mode while retaining the existing service executable and descriptor
  purposes;
- added same-directory mode-`0400` atomic output and exact-restart idempotence;
- retained the existing closed parser, fixed executable selection, empty child
  environment and descriptor cleanup boundaries.

## Evidence and validation

- targeted launcher and staging tests cover valid rendering, exact restart,
  wildcard/public/loopback/malformed IPs, missing or duplicate typed slots,
  unknown fields, unsafe modes, symlinks, duplicate paths and changed or partial
  output;
- full repository qualification is required before publication.

The reproducible offline candidate is bound to source commit
`25ec7901796208785ec25f20b5fc4c0d7bc05eba`:

| Artifact | SHA-256 |
|---|---|
| service executable | `598adbc49a727bffef773d97e724c915960e8404509e3b9d6941dd447040720c` |
| bootstrap executable | `73f59bec1ea4fd76baa6b3b637859e08fd88fe7ca0cb7530d59f85380214c923` |
| descriptor launcher | `f120742330e675d7b59e1e8e715fd3c4cefbedca8bbdc2add2ebb2f9192f35c7` |
| OCI manifest | `13b97c16c376d98767123bf78af5c16cb65ab09960b16fec122eb017317fefbe` |
| OCI config | `1ba350b044f511915bfc4076584d95494213aee63c441e103ac79eac148f223a` |
| OCI layer | `c273cf19b7bfed29ab6d1b775c5749ea947fd5a01a48c4fe95b1c8781bf755f4` |
| SPDX SBOM | `eede90b9eee7a5e98ef735abf3304657223fb197dc779c7a9d2363e9fe6ba064` |

Two complete offline OCI builds were byte-identical. These are local
qualification identities only; no registry publication or packet rebinding
occurred.

## Decisions discovered

The accepted exact private bind cannot be known in a static Kubernetes config,
and the approved scratch OCI cannot render it. Extending the already reviewed
launcher is the smallest boundary that preserves the no-shell and no-proxy
profile.

## Context impact

The source and launcher bytes supersede the currently bound OCI artifact. A
fresh reproducible OCI/SBOM build and immutable registry/packet rebinding are
required before Step 5 can be approved again.

## Risks and unresolved work

No registry, target, namespace, Kubernetes object, credential, listener or
traffic action is authorized by this implementation. Step 5 remains stopped.
