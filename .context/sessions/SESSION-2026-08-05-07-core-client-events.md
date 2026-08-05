# Session: core client events

- Date: 2026-08-05
- Governing issue: #6
- Accepted decision: RFC-0013

## Outcome

Added closed, canonical construction for `join`, `claim` and `progress`. Every
result passes the accepted protocol validator before publication.

## Boundary

No ambient discovery, credential access, publication, ownership decision,
Matrix integration or deployment is included.

## Next

Expose these builders through the CLI and implement the remaining question,
review and handoff families required by #7.
