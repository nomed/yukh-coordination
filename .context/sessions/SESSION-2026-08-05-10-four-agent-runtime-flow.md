# Session: four-agent runtime flow

- Date: 2026-08-05
- Governing issue: #7
- Accepted decision: RFC-0013

## Outcome

Four independently authenticated CLI runners completed the full coordination
flow through the real TLS handler and durable append path. Fifteen records and
their verified receipts were retained without user-mediated copying.

The test also corrected successor-claim correlation after an accepted handoff:
the successor opens a new root correlation but remains causally and
recipient-bound to the accepted offer.

## Boundary

The harness is hermetic and in-process. It is not a deployable relay and does
not yet satisfy the separate-process requirement of #7.

## Next

Run the same flow through two isolated CLI processes, retain the sanitized
transcript digest and replay it independently.
