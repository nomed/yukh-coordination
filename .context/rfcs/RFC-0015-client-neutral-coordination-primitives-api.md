# RFC-0015: Client-neutral coordination primitives API

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #55
- Governing architecture: ADR-0001, RFC-0002, RFC-0009, RFC-0011 and RFC-0012

## Decision requested

Freeze a bounded HTTPS boundary and a bundled TypeScript client through which
external runtimes can consume the RFC-0012 nonce and fenced-lease primitives
without importing Go `internal` packages, addressing NATS directly or invoking
a shell command.

Acceptance authorizes a separately reviewed implementation and deterministic
qualification of this boundary. It does not authorize deployment, a public
listener, production credentials, protected-operation policy, live apply or a
release. RFC-0006 relay routes and storage remain unchanged.

## Architectural boundary

The selected boundary is a distinct coordination-primitives service composed
over the accepted `NonceStore` and `FencedLeaseStore` ports. It is not a relay
route and does not read or write relay transcripts. It does not grant project
authority, approve a plan, hold protected-provider credentials or perform the
operation guarded by a nonce or lease.

The service owns bounded HTTP framing, authentication and authorization ports,
schema validation and translation to RFC-0012 values. The JetStream adapter
remains the only component that knows bucket names, subjects, KV revisions and
provider errors. External clients cannot select a NATS server, account, subject,
bucket, key prefix or storage operation.

The reference client is a small provider-neutral TypeScript package with no
runtime dependency. A consuming Node 24 Action bundles its compiled client at
build time. Consumer-time package installation, subprocess execution and direct
NATS dependencies are forbidden.

## Identity and authority

Every request passes through two mandatory ports before resource lookup:

1. `PrimitiveAuthenticator` returns one immutable principal and tenant binding;
2. `PrimitiveAuthorizer` decides one exact action for that binding and logical
   scope.

Production-capable construction has no nil, allow-all, header-derived or
environment-discovered fallback. Provider credentials are extracted only at the
HTTP edge and never reach RFC-0012 stores, values, diagnostics or audit output.
The initial implementation uses the RFC-0009 DPoP request-material shape and
public-target normalization, but uses a distinct audience and action namespace;
a relay session does not automatically authorize primitive operations.

Credential issuance, workload federation, GitHub OIDC exchange, private-key
custody and deployment configuration remain external. Tests use deterministic
deny-by-default fakes. A later deployment profile must select and qualify the
concrete authenticator and policy provider before exposing a listener.

Authorization actions are closed:

- `coordination.nonce.consume`;
- `coordination.lease.acquire`;
- `coordination.lease.inspect`;
- `coordination.lease.renew`;
- `coordination.lease.release`.

Authorization does not imply authority over the protected operation. The
protected consumer independently validates its plan approval, mutation
permissions and current fence immediately before irreversible work.

## Public operations

Version 1 exposes exactly these TLS-only routes under a separately configured
public base URI:

~~~text
POST /coordination-primitives/v1/nonces:consume
POST /coordination-primitives/v1/leases:acquire
POST /coordination-primitives/v1/leases:inspect
POST /coordination-primitives/v1/leases:renew
POST /coordination-primitives/v1/leases:release
~~~

There are no list, delete, watch, poll, batch, administrative or generic KV
routes. Requests have no query, cookies, content encoding or redirects and use
`application/yukh-coordination-primitives+json;version=1`. Each body is one
closed JCS-canonical UTF-8 object, at most 4 KiB and depth 4, with no duplicate
members. Responses are closed canonical objects at most 4 KiB and carry
`Cache-Control: no-store`.

### Scope and value inputs

Callers submit only already-derived lowercase SHA-256 digests:

- `scope_digest`: logical protected-resource scope;
- `value_digest`: nonce or approval value identity;
- `holder_digest`: lease holder identity;
- `epoch`: configured positive JSON-safe restore epoch;
- `expires_at`: UTC RFC 3339 with millisecond precision.

Raw repository, organization, Project, issue, tenant, participant, approval,
plan or credential content is invalid. The service derives the internal key by
domain-separated hashing of the authenticated tenant binding, operation family
and `scope_digest`; clients never receive the resulting store key.

Nonce consumption requires `scope_digest`, `value_digest`, `epoch` and
`expires_at`. Lease acquisition requires `scope_digest`, `holder_digest`,
`epoch` and `expires_at`. Expiry bounds are the strict configured RFC-0012
limits and are validated before a store call.

### Lease capability

A successful acquire returns an opaque `lease_capability`, the positive
JSON-safe `fencing_token`, and `expires_at`. The capability is a versioned,
authenticated-encrypted token containing only tenant binding, internal key,
holder digest, epoch, current lease revision, expiry and a random 128-bit token
identifier. It is confidential runtime material and must never enter logs,
Action output, reports, caches or command arguments. Its plaintext is never
returned to the client.

Inspect, renew and release accept exactly the capability and no caller-selected
key, holder, revision or fence. Renew returns a replacement capability carrying
the new current revision and fencing token. The previous capability is then
stale because RFC-0012 CAS ownership has advanced. Release writes the terminal
RFC-0012 value; reuse of the capability is stale. A capability expires no later
than the lease and is rejected when its authenticated tenant, configured epoch,
AEAD version or expiry does not match current service state.

Capability sealing is a mandatory port backed by an externally supplied AEAD
key provider. Production construction has no embedded, generated-on-startup or
environment-string key. The token envelope declares only a version and key ID;
the complete envelope is authenticated as associated data. Plaintext and keys
use locked/redacted wrappers at the provider boundary and are zeroed where the
runtime permits. Rotation retains decrypt-only keys no longer than the maximum
lease lifetime, while one active key seals new capabilities. Key loss fails
closed and cannot create a replacement lease identity.

This sealed indirection prevents raw RFC-0012 keys, holder digests and KV revisions
from becoming a public client contract while preserving the fencing token the
protected consumer must present to its downstream fence validator.

## Results and failure contract

Success responses contain `specversion: "1"`, one stable outcome and only the
fields required by that outcome. Nonce outcomes are `consumed` or `replayed`.
Acquire outcomes are `acquired` or `contended`. Inspect returns `valid`,
`expired`, `released` or `stale`. Renew returns `renewed`; release returns
`released`. A replay, contention, expiry or stale capability is a deterministic
non-success and never triggers an implicit retry.

Failures use bounded Problem Details with one stable code:

- `unauthenticated`;
- `access_denied`;
- `conflict`;
- `replayed`;
- `stale_fence`;
- `temporarily_unavailable`;
- `invariant_violation`;
- `invalid_request`.

Responses, errors and formatting exclude raw inputs, digests, capabilities,
keys, revisions, fencing tokens, epochs, expiry values, endpoints, credentials,
provider bodies and provider error text. Security audit records use a separate
closed contract and correlation-safe IDs only. Unknown provider failures and
ambiguous ownership map to `temporarily_unavailable`; malformed successful port
results map to `invariant_violation`. Neither case produces `2xx`.

Authentication precedes authorization, which precedes capability or store
lookup. Missing and unauthorized state share one non-enumerating denial shape.

## Call, time and retry bounds

One HTTP request invokes authentication once, authorization once, at most one
capability open or seal operation, and one RFC-0012 method. The RFC-0012 method
retains its fixed one mutation plus at most one exact read for ambiguous
acknowledgement. No layer watches,
polls, sleeps, performs background work, switches credentials or retries a
changed operation.

The server enforces one configured whole-request deadline no greater than five
seconds; clients must configure a shorter-or-equal explicit deadline and abort
once. The client performs no automatic retry. A caller may repeat only the exact
nonce request under its own deadline; lease operations require explicit
inspection after an ambiguous result and never infer ownership from timeout.

Concurrency, request-body bytes, response bytes, active capabilities per
principal, lease lifetime and nonce retention are all strictly configured and
reported as non-secret aggregate limits. Resource exhaustion fails closed.

## Packaging contract

The repository publishes source, generated JSON schemas and deterministic
fixtures for the TypeScript client. The client accepts only:

- an exact prevalidated HTTPS base URI;
- an explicit request-authentication callback returning bounded DPoP material;
- an explicit deadline and fetch-compatible transport.

It ignores proxy and provider environment variables, follows no redirect,
performs no discovery and returns typed stable outcomes rather than raw provider
bodies. Secret-bearing values use redacted wrappers and are not serializable.
The package is compiled and bundled into the consuming Action artifact; no
registry access or install step occurs during an Action run.

Package publication and immutable release qualification are separate gates.
The first implementation may be consumed only by repository tests until those
gates are explicitly accepted.

## Recovery and emergency disablement

Service startup verifies the RFC-0012 adapter epoch and configured capability
epoch agree. Absence, rollback, restore ambiguity or configuration mismatch
makes the service unready and denies every operation. Restoring into a new epoch
invalidates every prior capability and outstanding lease as required by
RFC-0012. Backup qualification covers the RFC-0012 stores; capability AEAD key
recovery and rotation are a separate declared failure domain and never roll the
coordination epoch backwards.

An operator can disable the entire primitives listener or deny each action at
the authorizer. Disablement creates no fallback to direct NATS, relay routes,
local locks or in-memory state. Rollback removes the service and bundled client;
RFC-0006 and RFC-0012 persisted state remain unchanged and inaccessible to
external clients.

## Required qualification

Implementation acceptance requires deterministic tests proving:

- exact route, media type, canonical schema, byte/depth and deadline bounds;
- authentication and authorization before existence disclosure;
- tenant-separated domain-derived keys and no caller-addressable KV surface;
- nonce first consume, exact/changed replay and concurrent consume;
- acquire contention, inspect, renew, release, expiry and stale-owner rejection;
- monotonic fencing and capability rotation without public revision exposure;
- fixed call counts, cancellation and ambiguous-ack reconciliation;
- no polling, sleep, hidden retry, redirect, proxy discovery or subprocess;
- redaction of credentials, capabilities, inputs, digests, revisions, endpoints
  and injected provider messages from every output path;
- restart, AEAD rotation, key loss, same-epoch recovery, restore-epoch
  invalidation and mismatch refusal;
- memory conformance and real disposable `nats-server` concurrency evidence;
- a Node 24 bundled-client fixture with the network disabled during build/run
  except for its synthetic in-process HTTPS target;
- RFC-0006 relay route and storage tests remain byte-identical and never open a
  KV bucket.

Tests do not claim deployment or protected-operation authorization. The exact
authenticator, authorizer, registry adapter and topology need separate review
before any listener can be described as deployable.

## Compatibility and sequencing

This is additive to RFC-0012 and changes no exported relay or protocol contract.
The accepted Go stores remain internal. Direct Go consumers inside this module
may keep using the neutral ports; external consumers use only this API.

After human acceptance, implementation may add the service ports, handlers,
capability sealer, bundled TypeScript client and synthetic qualification.
Deployment, live apply, consumer-specific configuration and publication remain
blocked. A protected consumer cannot be declared apply-compatible merely because
this transport exists.

## Alternatives rejected

### Direct NATS from Node

Rejected because it exposes provider credentials and storage topology, duplicates
RFC-0012 CAS/ambiguity logic and lets clients address subjects or buckets.

### A subprocess or coordination CLI extension

Rejected because bundled Actions must not depend on shell execution, PATH,
consumer-time installation or secret-bearing command arguments.

### Add the routes to the RFC-0006 relay

Rejected because nonce/lease state is operational fencing, not transcript
coordination, and would broaden the relay's accepted authority and storage path.

### Return raw keys and KV revisions

Rejected because it makes provider storage identity part of the public contract
and leaks sensitive correlation material. The sealed capability plus explicit
fencing token exposes only what the protected consumer needs.

### Introduce PostgreSQL

Rejected for this increment. JetStream is already an accepted dependency and
RFC-0012 has qualified the necessary atomic primitives; an additional database
would add operational and recovery domains without removing the need for the
existing adapter.
