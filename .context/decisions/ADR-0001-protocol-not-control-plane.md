# ADR-0001: Coordination protocol, not authority control plane

- Status: Accepted
- Date: 2026-08-02

## Context

Isolated sessions need a shared coordination surface. Combining communication with execution authority would make the relay a privileged orchestrator and couple every adopter to its identity, policy, and credential model.

## Decision

Yukh Coordination defines and implements an open coordination protocol. It records participant signals, claims, evidence references, reviews, and explicit handoffs. It does not grant capabilities, hold adopter credentials, choose execution owners, or override project governance.

Authority remains external and may be supplied by repository rules, a claim registry, Yukh MCP, Yukh Projects, or another compatible system.

## Consequences

- clients can adopt coordination without delegating operational custody;
- the protocol must represent conflicts rather than resolving them invisibly;
- adapters may integrate authority systems, but the core remains neutral;
- the first reference implementation can remain small and replaceable.
