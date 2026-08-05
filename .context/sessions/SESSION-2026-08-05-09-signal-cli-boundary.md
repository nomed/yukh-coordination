# Session: signal CLI boundary

- Date: 2026-08-05
- Governing issue: #6
- Accepted decision: RFC-0013

## Outcome

Exposed the complete coordination signal vocabulary through explicit command
names and one bounded, closed JSON input. Successful output contains generated
event/claim/handoff bindings plus the verified publication receipt.

## Boundary

The host still supplies the authenticated publisher and credential custody.
No executable, ambient discovery, retry, Matrix integration or deployment is
included.

## Next

Compose the qualified isolated CLI processes and run the #7 four-agent proof.
