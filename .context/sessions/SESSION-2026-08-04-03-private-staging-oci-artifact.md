# Session 2026-08-04 — RFC-0022 offline OCI artifact

## Authority and scope

- Governing issue: #141
- Operator-packet issue: #136
- Accepted design: RFC-0022
- Source candidate: `d122f31ce6a74dcec97dfcf8095a4447e23ee593`
- Source tree: `a59ba3f7ad6018d96f7329710eb593766acda676`

## Delivered candidate

- deterministic OCI `scratch` layout for Linux AMD64;
- exact previously reviewed service and bootstrap binary digests;
- numeric non-root identity, fixed service entrypoint and empty working path;
- complete layer allowlist with no shell, package manager or downloader;
- deterministic OCI configuration, manifest, layer and SPDX 2.3 inventory;
- two-build byte equality and closed blob/configuration qualification in CI.

The local double build produced manifest
`f3ae988c7aab21a1492e4108d45a3bafdd1d25b9431378d3fab8ef0a11aa7636`,
configuration
`4be24611d67628889075d1782530d9b8822dda0ffc6396b157b14dc9e7f7872d`
and layer
`83be76c5dcfe0a613f380df70dcf772beae89546a7f607256287d013e51b8362`.
The adjacent deterministic SPDX document is
`bd0a9fc0e7487acdb3755792a82a466d312decfabd86d83fb285e9b4a0334a88`.

## Intentionally incomplete

No image is pushed, signed, installed or loaded. No registry, private target,
namespace, Kubernetes resource, credential, listener or request is touched.
The operator packet still requires review of the resulting OCI digests,
private runtime inputs and an independent reproducer.

## Next boundary

After review and merge, bind the OCI digests and closed Kubernetes runbook into
#136. Only a complete packet can be presented for the separate RFC-0022 step-5
owner approval; live traffic remains a later independent gate.
