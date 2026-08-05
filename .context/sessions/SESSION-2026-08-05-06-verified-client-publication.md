# Session: verified client publication

- Date: 2026-08-05
- Governing issue: #6
- Accepted decision: RFC-0013

## Outcome

Added bounded canonical event publication through the real HTTP handler. The
client verifies the signed receipt and its exact event, channel and transcript
binding before reporting `appended` or `duplicate`.

## Boundary

No event construction, participant selection, credential storage, CLI command,
server deployment, Matrix bridge or authority is added.

## Qualification

- focused client and CLI tests;
- focused `go vet`;
- real-handler publication and receipt-binding test;
- `git diff --check`.

## Next

Expose closed signal construction and CLI commands, then run the isolated
two-session/four-agent qualification required by #7.
