# Session 2026-08-04 — RFC-0022 Kubernetes descriptor launcher

## Authority and scope

- Governing issue: #144
- Operator-packet issue: #136
- Accepted design: RFC-0022
- OCI prerequisite: #141 / PR #142

## Delivered candidate

- one compiled closed launcher for exact `service` and `bootstrap` modes;
- bounded non-symlink secret-file validation with identity recheck;
- collision-safe mapping to descriptors 3/4 and close-on-exec cleanup;
- empty child environment and fixed executable selection;
- negative tests for argument, path, permission, empty-file, duplicate-file,
  symlink, missing-file and closed-process cases;
- superseding deterministic OCI and SPDX digests containing three executables.

## Local qualification

| Artifact | SHA-256 |
|---|---|
| descriptor launcher | `08d7dd79b9cc8afe68f9a2ccc367771157f6c6ee1856a7571dbe39f8e9a4f821` |
| OCI manifest | `27ee06d3cc2a0b804424625e2570e3018b22bdd9b0dba7c28cd54e3b05d6ce7b` |
| OCI config | `76f3d6db4b35ef6fe66b6f0b61627428f1f0d8327d4d52ee23032f3d30df9db5` |
| OCI layer | `bed142fd3b1e8ce5f248de1d0f7068a9c837bfc563ab8d9a86fcb365186f2848` |
| SPDX SBOM | `2c6d1bc52e47fcecb0d60342719819e6fc99e486a6d398086a3bfbba81cbea13` |

## Intentionally incomplete

No image is pushed or loaded and no target, namespace, Secret, workload,
listener or request is touched. Independent digest reproduction, immutable
registry binding and the remaining private operator evidence are still
required before step-5 approval can be requested.

## Next boundary

After review and merge, update the execution-forbidden private Kubernetes
runbook with the superseding OCI and launcher digests and finish #136. Only a
complete reviewed packet may be presented for explicit step-5 approval.
