# Session: Single-node process profile review

- Date: 2026-08-03
- Governing issues: #3 and #5
- Accepted decision: RFC-0008
- Branch: `agent/single-node-provider-profile-rfc`

## Outcome

Accepted the complete provider and operational profile required before the
reference relay may become a process binary. The review found that provider
wiring alone is insufficient: finite transcript lifecycle, security audit,
live revocation and operational isolation are also mandatory gates from the
accepted threat model.

RFC-0008 selects a single-node SQLite profile with RFC 9068 external bootstrap,
relay-issued opaque DPoP-bound sessions, a signed closed policy/channel
manifest, separate identity and audit databases, Vault Transit Ed25519 receipt
signing, direct public TLS and a loopback-only operational surface.

JetStream remains a qualified adapter but is intentionally excluded from this
first process profile until the surrounding security state has a distributed
design.

## Boundary

This session changes documentation only. It adds no route, provider,
dependency, database, secret, `cmd/` directory or deployment configuration.
The next authorized increment is the focused session-bootstrap contract. It
does not authorize a provider, database schema or executable composition.
