# JetStream state and secret boundaries

Yukh Coordination uses NATS JetStream as a bounded runtime dependency in its
private staging profile. JetStream stores three classes of coordination state.
It is not the only durable state in the profile, and it does not replace
credential custody, identity, TLS, audit, or capability-key management.

This is an explanation of the intended, gated profile. It is not an
installation guide and does not indicate that a live NATS server, bucket,
credential, listener, or traffic path exists.

The accepted
[RFC-0022](https://github.com/nomed/yukh-coordination/blob/main/.context/rfcs/RFC-0022-private-staging-primitives-service.md),
[deployment plan](https://github.com/nomed/yukh-coordination/blob/main/.context/security/private-primitives-staging-deployment-plan.md),
[implementation record](https://github.com/nomed/yukh-coordination/blob/main/.context/security/private-primitives-staging-implementation-record.md),
[redacted operator packet](https://github.com/nomed/yukh-coordination/blob/main/.context/security/private-primitives-staging-operator-packet.md),
and
[threat model](https://github.com/nomed/yukh-coordination/blob/main/.context/security/threat-model.md)
remain authoritative.

## Separate executable and custody boundaries

```text
reviewed OCI
    -> one-shot bootstrap executable
       -> bootstrap NATS credential
       -> create or exactly verify three buckets
       -> exit, then revoke and destroy the credential
    -> normal service executable
       -> runtime NATS credential
       -> open and exactly verify the same three buckets
       -> serve only after all readiness gates pass
```

The OCI packages the reviewed executables and closed launcher. It contains no
NATS credential, TLS private key, capability keyring, workload token, or DPoP
private key. Changing any packaged executable or launcher bytes invalidates the
reviewed OCI binding.

The one-shot bootstrap executable and normal service executable are not
interchangeable:

- bootstrap has no listener, service runtime, registration, capability key,
  replay database, or audit database access;
- bootstrap may only create missing buckets or verify their complete immutable
  configuration and positive restore epoch;
- normal service start always disables bucket creation and fails closed unless
  all three existing buckets exactly match the reviewed profile and epoch.

The selected profile permits only a literal loopback `nats://` target. The NATS
server and Coordination process are co-located inside the isolated staging
boundary, but remain separate processes. Remote NATS, TLS NATS, clustering,
service discovery, and automatic failover are outside this profile.

## The three JetStream KV buckets

Only these JetStream key-value buckets belong to the profile:

| Bucket | State it holds | Why it exists |
| --- | --- | --- |
| `YUKH_COORDINATION_NONCES_V1` | Consumed external nonces | Prevents an external request from being replayed. |
| `YUKH_COORDINATION_LEASES_V1` | Current and terminal fenced-lease values and revisions | Prevents stale or concurrent holders from acting as current. |
| `YUKH_COORDINATION_CAPABILITY_BUDGET_V1` | Bounded capability-accounting reservations | Enforces the configured capability resource limit. |

These buckets are JetStream-managed state stores. They are not object storage,
secret stores, or a substitute for an approval system. The bucket names do not
grant access; NATS authorization and the selected custody profile do.

Nonce reuse is never made safe by deletion or expiry. Lease release writes a
terminal value rather than deleting the key, and rollback preserves terminal
and fencing state. A restore uses a positive epoch shared by the service and
all three buckets; mismatch, rollback, or ambiguity denies readiness.

## State outside JetStream

JetStream does not hold every durable record needed by the service:

| State | Storage boundary | JetStream access |
| --- | --- | --- |
| DPoP proof replay reservations | Dedicated local SQLite database | None |
| Mandatory authentication, authorization, readiness, key-lifecycle, and storage audit | Separate local SQLite audit ledger | None |
| Signed public workload registration | Supervisor-owned regular file | None |
| Closed non-secret configuration | Supervisor-owned bootstrap file; supervisor-provided service template and launcher-rendered mode-`0400` service file in a private process-owned directory | Names and configures the exact NATS profile, but contains no credential |

The replay and audit databases are separate from the NATS process and its
storage. The rendered service configuration is not a secret; its private
directory prevents replacement or ambiguous reuse. The NATS container does not
mount that directory. Losing any required state or exact configuration evidence
fails readiness; one store is never treated as a backup authority for another.

## Secrets and identities stay outside JetStream

Each sensitive input has one purpose and delivery boundary:

| Material | Recipient and delivery | Lifetime and authority |
| --- | --- | --- |
| Bootstrap NATS credential | One-shot bootstrap executable through its inherited descriptor | Short-lived; only the fixed create/verify operations; revoked and destroyed after bootstrap |
| Runtime NATS credential | Normal service through a distinct inherited descriptor | Only reviewed runtime operations on the fixed buckets; held by the adapter until connection close, then cleared |
| Capability keyring | Normal service through its own inherited descriptor | Seals lease capabilities; never available to bootstrap or NATS |
| TLS private key | Normal service through a supervisor-owned, non-writable regular file | Establishes the exact private service identity; never available to NATS |
| Workload token and DPoP private key | Future MCP consumer through distinct inherited descriptors | At most 15 minutes; never enter Coordination or NATS |

Coordination receives only the signed public registration for the workload
token and DPoP key. The future MCP consumer receives no NATS connection
information or NATS credential.

Putting a credential into a JetStream bucket would collapse the boundary the
profile is designed to preserve. A NATS credential authorizes access to the
buckets; it is never data stored by them.

## Why OCI rebinding blocks Step 5

A launcher or runtime-directory correction changes the OCI bytes that would run
both reviewed executable paths. It does not change JetStream's purpose, but it
invalidates the prior artifact binding.

Before Step 5 can be reassessed:

1. the corrected OCI must be independently reproduced and its complete
   executable and layer allowlist verified;
2. separately authorized publication must produce an immutable registry digest,
   and a pull by that digest must match the reviewed manifest, configuration,
   and layer bytes;
3. the implementation record, deployment plan, threat model, and redacted
   operator packet must bind those exact identities;
4. the packet must still contain current trust, credential-policy, limits,
   restore-epoch, filesystem, rollback, and time-valid certificate evidence;
5. the project owner must explicitly approve that complete, digest-specific
   packet.

Preparation, offline reproduction, documentation, or a passing repository check
does not satisfy those gates.

Issue #184 records byte-identical offline candidate builds from the corrected
source. Those local candidate identities are preparation evidence only: they
remain non-deployable until separately authorized publication, provider pull
comparison, record and packet rebinding, and a fresh owner decision.

## Current maturity boundary

The adapters, distinct bootstrap and service executables, and disposable-server
qualification exist in the repository. That is hermetic implementation
evidence, not evidence of a live deployment.

The current Step 5 path is paused at
[issue #184](https://github.com/nomed/yukh-coordination/issues/184) while the
corrected OCI binding is renewed. No live bucket, NATS credential, NATS pod,
TLS identity, capability keyring, workload credential, listener, or MCP traffic
is implied by this documentation.

Even a later Step 5 approval would authorize provisioning with the public
listener blocked and no network request. Step 6 must independently verify the
resulting no-traffic evidence. A separate Step 7 owner approval would still be
required before any bounded synthetic MCP request. See
[issue #167](https://github.com/nomed/yukh-coordination/issues/167) for the
gated no-traffic provisioning path.
