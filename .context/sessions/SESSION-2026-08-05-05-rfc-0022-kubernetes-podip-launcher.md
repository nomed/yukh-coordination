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
