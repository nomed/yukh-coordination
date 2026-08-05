# Session 2026-08-05 — RFC-0022 immutable registry binding

## Authority and scope

- Parent issue: #136
- Governing issue: #159
- Governing architecture: accepted RFC-0022 and RFC-0024
- Scope: separately authorized GHCR publication and public record binding

## Closed evidence

- exact OCI layout rebuilt from delivery commit
  `83411ebf6b3a86b55ec527dfd40908a402e07c1a` with the accepted Go `1.26.5`
  toolchain and all five artifact digests reproduced;
- one private GHCR package version published;
- provider-observed OCI manifest digest exactly
  `sha256:27ee06d3cc2a0b804424625e2570e3018b22bdd9b0dba7c28cd54e3b05d6ce7b`;
- authoritative owner-only digest pull identity recorded in the operator packet;
- no repository Actions access granted;
- temporary publisher login state, toolchain, OCI layout and worktree destroyed;
- owner accepted the bounded residual risk from using the existing operational
  PAT rather than a one-shot package-write-only publisher.

## Current boundary

No pre-step-5 packet field remains pending, but the server leaf expires at
`2026-08-06T08:01:13Z`. The packet is only
`READY_TO_REQUEST_STEP_5_APPROVAL_TIME_CRITICAL`: this record neither requests
nor grants Step 5. Target pull, Kubernetes Secret or namespace creation,
credential generation, listener start, MCP connection and traffic remain
forbidden without their separate explicit decisions.
