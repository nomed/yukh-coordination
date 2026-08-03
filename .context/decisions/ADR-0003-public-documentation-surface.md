# ADR-0003: Component-owned public documentation

- Status: Accepted
- Date: 2026-08-03
- Decider: project owner
- Governing issue: #122

## Context

The suite documentation architecture assigns tutorials, task guides, reference,
explanations and security guidance to each component repository. Coordination
has enough executable conformance and replay material to need persistent
navigation, but its engineering records must remain authoritative in `.context/`.

## Decision

Add `documentation/` as the source for concise public component documentation.
It may link to accepted records but cannot duplicate or supersede them. The site
states maturity and provides only workflows executable at the current boundary.

## Consequences

- `documentation/` becomes part of the closed top-level map.
- `.context/` remains the sole engineering-memory and decision root.
- publication does not authorize deployment, credentials, live traffic or production use.
