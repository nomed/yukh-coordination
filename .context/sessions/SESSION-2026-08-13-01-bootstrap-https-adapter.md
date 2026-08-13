# Session: bootstrap HTTPS adapter

- Date: 2026-08-13
- Governing issue: #6
- Accepted decision: RFC-0014

## Outcome

The client bootstrap saga now has an exact HTTPS exchange and CLI boundary.
The adapter creates a fresh DPoP proof, rejects redirects and accepts only the
closed canonical session response.

## Next

Compose explicit local custody and receipt verification in the executable.
