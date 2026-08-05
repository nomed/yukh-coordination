# JetStream state and secret boundaries

Yukh Coordination uses NATS JetStream as a bounded runtime dependency in its
private staging profile. JetStream stores coordination state. It does not
replace credential custody, identity, TLS, or capability-key management.

This is an explanation of the intended, gated profile. It is not an
installation guide and does not indicate that a live NATS server, bucket,
credential, listener, or traffic path exists.

## Four separate layers

```text
reviewed OCI image
    -> starts the Coordination executable
    -> consumes custody-delivered runtime material
    -> authenticates to local NATS JetStream
    -> reads and updates bounded coordination state

separate custody boundary
    -> holds NATS credentials, TLS identity, and capability material
```

The OCI image packages reviewed executable bytes and a closed launcher. It
does not contain a NATS credential, TLS private key, capability keyring, token,
or DPoP key.

The NATS JetStream server is a separate runtime dependency in the isolated
staging boundary. It stores state only after the Coordination process has
authenticated with a separately delivered, least-privilege NATS credential.

## The three JetStream KV buckets

The private staging bootstrap creates and verifies exactly these three
JetStream key-value buckets:

| Bucket | State it holds | Why it exists |
| --- | --- | --- |
| `YUKH_COORDINATION_NONCES_V1` | Consumed external nonces | Prevents an external request from being replayed. |
| `YUKH_COORDINATION_LEASES_V1` | Fenced lease state | Prevents stale or concurrent holders from acting as current. |
| `YUKH_COORDINATION_CAPABILITY_BUDGET_V1` | Bounded capability accounting state | Enforces the configured capability resource limit. |

These buckets are JetStream-managed state stores. They are not object storage,
secret stores, or a substitute for an approval system. The bucket names do not
grant access; NATS authorization and the selected custody profile do.

## Credentials are outside JetStream

The profile separates three categories of sensitive material from the buckets:

| Material | Boundary | Purpose |
| --- | --- | --- |
| Bootstrap NATS credential | One-shot bootstrap custody | Creates and verifies the fixed buckets, then is revoked and destroyed. |
| Runtime NATS credential | Runtime custody | Grants only the reviewed operations on the fixed buckets. |
| TLS identity and capability keyring | Independent custody boundaries | Establishes the private service identity and governed capability semantics. |

An MCP consumer, only after its own later gate, receives distinct short-lived
consumer material. It does not receive NATS connection information or a NATS
credential.

Putting a credential into a JetStream bucket would collapse the boundary the
profile is designed to preserve. A NATS credential authorizes access to the
buckets; it is never data stored by them.

## Why OCI rebinding blocks bucket creation

The three buckets are created only by the reviewed bootstrap executable running
in the reviewed Coordination deployment composition. A launcher or runtime
directory correction changes the OCI bytes that are allowed to start that
composition. It does not change JetStream's purpose, but it invalidates the
prior artifact binding.

Before a bucket can be created after such a change, the corrected OCI must be
independently reproduced, published and verified by digest, and rebound into
the redacted operator packet. The owner must then approve the renewed Step 5
packet. This prevents an approved bootstrap operation from silently running
different executable bytes.

## Current maturity boundary

The JetStream adapter and disposable-server qualification exist in the
repository. The private staging bootstrap is designed to create and verify the
three buckets during the separately approved no-traffic Step 5.

The current Step 5 path is paused at
[issue #184](https://github.com/nomed/yukh-coordination/issues/184) while the
corrected OCI is rebound. No live bucket, runtime NATS credential, NATS pod,
listener, or MCP traffic is implied by this documentation. See
[issue #167](https://github.com/nomed/yukh-coordination/issues/167) for the
gated no-traffic provisioning path.
