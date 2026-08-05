# Session 2026-08-05 — RFC-0024 server-leaf rotation execution

## Authority and scope

- Parent issue: #136
- Governing issue: #163
- Qualified implementation: PR #164, commit
  `65e31e50eda18e9737da517f207be1e1d882a984`
- Scope: owner-authorized offline server-leaf rotation only

## Closed evidence

- attempt 1 aborted before custody mutation because route-isolated execution
  produced root-owned output; v1 survived, v2 was absent and plaintext was
  destroyed;
- attempt 2 generated as the owner UID/GID inside a route-free network
  namespace and passed the merged verifier;
- trust-bundle SHA-256 remained
  `ac9560e118851b63b7b40678fd9c3afe09fd35b13198946b7f038cc30a8a0115`;
- selected leaf-certificate SHA-256 is
  `445e7758bdcff2ab94c01776dc6918914d9ccb4c4457425d758216611a017133`;
- selected leaf expiry is `2026-08-06T11:05:05Z`;
- versioned encrypted custody creation, private-note digest reopen, certificate
  and receipt attachment reopen all passed;
- a fresh reviewer workspace reopened public evidence from custody and passed
  the merged verifier with the same digests;
- encrypted v1 remains only as rollback and v2 is the selected leaf;
- all tmpfs plaintext, temporary executables and execution worktree were
  destroyed, and the Vaultwarden client was locked.

## Current boundary

The packet remains `READY_TO_REQUEST_STEP_5_APPROVAL_TIME_CRITICAL`. Rotation
does not request or authorize target pull, Kubernetes credentials or objects,
Step 5, listener start, MCP connection or traffic. Another leaf rotation is
required if a safe Step-5/Step-6 interval cannot complete before the selected
leaf expires.
