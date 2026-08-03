# JetStream KV coordination adapter

This package implements the separate RFC-0012 nonce and fenced-lease storage
capability. It does not participate in the RFC-0006 relay read/write path and
does not store protocol records, approvals, repository data or credentials.

The adapter opens only `YUKH_COORDINATION_NONCES_V1` and
`YUKH_COORDINATION_LEASES_V1`. Bootstrap is explicit. File storage, replica
count, retention, history, maximum value size, adapter version and recovery
epoch must match exactly; mirrors, sources and republish are rejected. Keys and
stored identities are lowercase SHA-256 digests.

Each operation performs one mutation and at most one reconciliation read. There
are no watchers, polling loops, sleeps, background retries or credential
fallbacks. Public callers receive only stable coordination error classes.

Operationally, backup and restore must include both bucket configurations and
entries. A restore keeps the old epoch fenced: opening with a newer epoch fails
until an accountable operator explicitly rotates or migrates both buckets.
NATS credentials should grant only the JetStream API and subjects required by
these two KV buckets. Deployment, bucket rotation, backup retention and live
apply authorization remain outside this package.
