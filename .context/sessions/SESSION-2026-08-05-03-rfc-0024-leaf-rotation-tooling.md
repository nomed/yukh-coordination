# Session 2026-08-05 — RFC-0024 leaf-rotation tooling

## Authority and scope

- Parent issue: #136
- Governing issue: #163
- Governing architecture: accepted RFC-0024
- Scope: qualified leaf-only offline tooling; no custody mutation in this record

## Delivered candidate

- exact absolute/mode-checked existing-root inputs;
- root certificate/private-key match and full validity-window checks;
- fresh ECDSA P-256 server key and root-signed 24-hour leaf for the unchanged
  exact private identity;
- three-file closed output with no copied root material;
- canonical redacted leaf-rotation receipt;
- independent verification of trust digest, root key ID, exact SAN, chain,
  algorithm, server-auth use, validity and leaf digest;
- negative tests for unsafe root modes, wrong identity and partial output.

## Next boundary

After review and merge, the already authorized private rotation may use this
exact executable only through a separately qualified atomic custody-replacement
helper. Trust-root/policy rotation, registry mutation, target pull, Kubernetes
objects, Step 5, MCP connection and traffic remain forbidden.
