# SESSION-2026-08-05-14: RFC-0022 non-root runtime directory

- Governing issue: #182
- Parent execution issue: #167
- Pull request: #183
- Status: implementation candidate

## Objective

Close the kubelet-owned writable-volume mismatch without adding a privileged
launcher, init image, shell or relaxed rendered-config boundary.

## Work completed

- extended the existing PodIP-aware launcher to create one absent UID-owned
  mode-`0700` private child under an exact mode-`0770`, effective-GID-owned
  Kubernetes mount root;
- require an existing private child to retain exact UID ownership and mode;
- permit only an empty child or the one expected output name;
- retain atomic mode-`0400` rendering and exact restart idempotence.

## Evidence and validation

Hermetic tests cover successful private-child creation, exact restart,
world-writable mount rejection, unsafe existing-child mode, symlink rejection,
ambiguous pre-population and the prior PodIP/output negative matrix.

## Decisions discovered

The mount root is a staging area, not the trusted configuration parent. The
launcher can safely create its own narrower child using only the existing
non-root identity; no Kubernetes ownership helper is required.

## Context impact

Launcher and OCI bytes are superseded again. Step 5 remains paused after the
namespace/storage/network/registry-pull foundation until fresh reproducible OCI
and packet evidence are reviewed and rebound.

## Risks and unresolved work

The writable mount is exclusive to the Coordination container. If that
exclusivity cannot be proven by the workload manifest, deployment rejects.
No NATS/service pod, credential, bootstrap, listener, MCP request or traffic
is authorized by this implementation.
