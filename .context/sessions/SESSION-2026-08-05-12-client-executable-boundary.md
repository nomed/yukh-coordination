# Session: client executable boundary

- Date: 2026-08-05
- Governing issue: #6
- Accepted decision: RFC-0013

## Outcome

The `yukh-coordination` process now owns one closed dispatcher for the accepted
command vocabulary. `help` and `version` run directly; missing network and
credential composition fails closed.

## Next

Compose bootstrap, encrypted local custody, DPoP authorization and receipt-key
verification without adding token arguments or plaintext fallback.
