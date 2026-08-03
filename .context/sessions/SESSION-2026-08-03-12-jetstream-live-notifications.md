# Session: JetStream live notifications

- Date: 2026-08-03
- Governing issue: #5
- Governing RFCs: RFC-0005 and RFC-0006
- Branch: `agent/jetstream-live-notifications`

## Outcome

Implemented the JetStream live wake-up path on the distributed Store adapter.
`Subscribe` creates an ephemeral ordered consumer with `DeliverNewPolicy` and
an exact hashed tenant-subject filter before returning. Pull and application
buffers are bounded to one message, so bursts coalesce without carrying
transcript data.

`Notify` is intentionally a no-op: successful Store mutations already publish
the durable command. Core NATS is not introduced as a duplicate at-most-once
signal path.

## Evidence

- subscribe-before-read interleaving observes both durable state and a wake-up;
- commands from another tenant do not wake the subscription;
- same-tenant commands may coalesce into one bounded hint as designed;
- explicit unsubscribe and context cancellation close the channel and delete
  the server-side consumer;
- terminal NATS connection failure closes the subscription;
- repeated real-server package tests, complete Go suite and `go vet` pass.

## Boundary

Notifications remain non-authoritative wake-up hints. They contain no record,
Yukh cursor or JetStream sequence. Matrix integration, executable process
composition, deployment topology and production operations remain outside this
increment.
