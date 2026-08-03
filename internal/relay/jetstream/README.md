# JetStream adapter

This package implements the accepted RFC-0006 boundary. KV is not used. The
authoritative model is one canonical command log per hashed tenant subject.

The adapter verifies connection bootstrap, tenant subject derivation and the
exact fail-closed stream profile against a real `nats-server`. It implements
`relay.Store` through canonical closed commands, deterministic full-log replay,
per-tenant-subject optimistic concurrency and identity-based reconciliation of
ambiguous publish acknowledgements.

Live notification is deliberately separate. Until the next qualified
increment implements the application `SubscriptionSource`, this package is a
durable Store adapter rather than a complete relay runtime adapter.

No NATS credentials, endpoint defaults or deployment topology belong here.
