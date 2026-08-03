# Session 2026-08-03 — accountable RFC-0022 bucket bootstrap

## Authority and scope

- Governing issue: #90
- Bounded increment: #117
- Accepted designs: RFC-0012, RFC-0019 and RFC-0022
- Prerequisite: executable delivery #115 merged through #121
- Downstream dependency: `nomed/yukh-mcp#50`, still blocked

## Delivered candidate

- a separate one-shot bootstrap executable with one absolute non-secret config;
- one inherited short-lived NATS credential descriptor, captured before file
  access, bounded, memory-locked where supported, closed and zeroed;
- create-or-exactly-verify composition of only the nonce, lease and
  capability-budget buckets through the existing accepted adapters;
- no update, delete, purge, migration, repair, listener or service-runtime path;
- canonical redacted receipt binding schema, profile, source revision, epoch,
  bucket-profile digest and closed outcome;
- reproducible artifact qualification plus hermetic create/rerun verification
  against disposable JetStream.

## Intentionally incomplete

No real infrastructure, credential, bucket, listener or traffic is created.
The immutable implementation record and execution-forbidden deployment plan
still identify the earlier candidate and require a separate reconciliation.
MCP integration, provider execution, protected mutation and production use
remain excluded.

## Next boundary

After #117 is reviewed and merged, publish a record-only reconciliation of the
new immutable commit/tree, both executable artifacts and deployment plan. Only
then may the owner be asked for the distinct provisioning approval required by
RFC-0022; a live synthetic window remains a second later approval.
