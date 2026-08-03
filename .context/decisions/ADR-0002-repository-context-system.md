# ADR-0002: Repository-owned context system

- Status: Accepted
- Date: 2026-08-03
- Decider: project owner
- Governing pull request: #16

## Context

Yukh Coordination is developed across agents, tools and sessions. Component
decisions were previously split across `docs/adr`, `docs/rfc` and
`docs/security`, while the other Yukh components had begun adopting `.context`.
The split obscured where durable engineering memory lived and allowed parallel
taxonomies to emerge.

## Decision

`.context/` is the sole canonical home for component ADRs, RFCs, security
models, session summaries and handoffs. Accepted records are moved without
changing their authority or history. Repository presentation assets belong to
`.github/assets`; implementation tests belong beside their implementation.

The top-level directory map in `.context/README.md` is closed. Adding another
top-level directory requires an accepted decision with a distinct current
responsibility.

## Consequences

Humans and agents have one deterministic context-loading path. Links and
conformance manifests must follow canonical record locations. Empty ceremonial
directories and duplicate compatibility copies are not retained.

## Security

`.context` is public. Credentials, secrets, private reasoning, unrestricted
transcripts, personal data and adopter-specific infrastructure details are
forbidden.

## Evidence

- all tracked paths are covered by the repository map;
- no `docs/` or root `test/` compatibility tree remains;
- protocol, conformance and runtime tests remain green after relocation.
