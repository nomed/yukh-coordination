# JetStream adapter

This package implements the accepted RFC-0006 boundary. KV is not used. The
authoritative model is one canonical command log per hashed tenant subject.

The adapter verifies connection bootstrap, tenant subject derivation and the
exact fail-closed stream profile against a real `nats-server`. It implements
`relay.Store` through canonical closed commands, deterministic full-log replay,
per-tenant-subject optimistic concurrency and identity-based reconciliation of
ambiguous publish acknowledgements.

The same adapter implements the application live-notification shape with an
ephemeral JetStream consumer filtered to the exact tenant subject. Setup
completes before the first durable read, wake-ups are bounded and coalesced,
and cancellation removes the server-side consumer. Notifications never carry
records or cursors: durable Store reads remain authoritative.

No NATS credentials, endpoint defaults or deployment topology belong here.
