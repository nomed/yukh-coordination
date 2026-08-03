# JetStream adapter

This package implements the accepted RFC-0006 boundary. KV is not used. The
authoritative model is one canonical command log per hashed tenant subject.

The first increment freezes and verifies connection bootstrap, tenant subject
derivation and the exact fail-closed stream profile against a real
`nats-server`. Command codec, reducer, optimistic append/reconciliation and live
consumer delivery follow in the next focused increment; this package does not
yet implement `relay.Store` and cannot be used by a relay runtime.

No NATS credentials, endpoint defaults or deployment topology belong here.
