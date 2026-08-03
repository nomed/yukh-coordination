# SESSION-2026-08-03-06: Relay application contract

- Governing issue: #5
- Pull request: pending
- Status: Active

## Objective

Close the canonical serialization and replay-to-live race boundary before
implementing the concrete application service.

## Findings

- RFC-0004 fixes transport behavior but not the byte-exact transcript page and
  canonical record object.
- The existing persistence port does not expose the complete immutable channel
  metadata required for channel validation and receipt construction.
- A read-then-subscribe implementation would contain a lost-wakeup race.
- Durable reads must remain authoritative; live notifications are only hints.

## Action

Proposed RFC-0005 with exact page/record shapes, receipt construction sources,
channel metadata lookup and subscribe-before-read semantics. No application
code or new dependency is introduced before owner acceptance.

## Next

Obtain owner review of RFC-0005, then implement it as a separate application
increment governed by issue #5.
