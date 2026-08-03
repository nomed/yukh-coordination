# Session: Lease-acquisition contention clarification

- Date: 2026-08-03
- Governing issue: #83
- Pull request: pending
- Accepted decision: RFC-0021
- Scope: immutable contract clarification only

## Outcome

Recorded the owner's accepted decision that a contended Coordination primitives
v1 lease acquisition returns bounded Problem Details with HTTP `409` and code
`conflict`. `contended` is not a successful `2xx` outcome. RFC-0021 supersedes
only the contradictory sentence in RFC-0015 and leaves every other accepted
boundary unchanged.

## Evidence

The merged schema excludes `contended` and admits `conflict`; the dependency-free
client accepts only `acquired` as acquisition success and validates `409
conflict`; the handler maps the internal conflict to that Problem Details shape;
and the existing bridge test proves a contending second holder receives it.

## Boundary

No executable source, schema, client, handler, fixture, route, storage,
credential, deployment or live operation changed. This record transfers no
ownership of closed issue #58 and authorizes no change in Yukh MCP. It unblocks
MCP compatibility review only after this record merges.
