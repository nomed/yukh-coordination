# RFC-0022: Private staging Coordination primitives service

- Status: Draft
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #90
- Governing architecture: RFC-0002, RFC-0011, RFC-0012, RFC-0015, RFC-0016, RFC-0017, RFC-0019 and RFC-0021

## Summary

Select the first deployable Coordination primitives profile as one Linux
process on a private staging network. The process terminates TLS directly,
exposes only the five accepted RFC-0015 operations, composes the qualified
JetStream KV nonce and fenced-lease stores, and admits one explicitly
provisioned DPoP-bound workload identity under a closed five-action policy.

The profile identifier is
`yukh-coordination/private-primitives-staging-v1`. It exists to qualify a real
MCP-to-Coordination connection with synthetic operation bindings. It is not a
production, multi-tenant, high-availability or protected-operation profile.

Acceptance authorizes separately reviewed implementation and hermetic
deployment qualification. It does not provision infrastructure, mint a live
credential, expose a listener, authorize live staging traffic, connect MCP,
invoke a provider, mutate a protected target or authorize production use.

## Motivation

RFC-0015 froze and qualified the public wire contract but deliberately left
the concrete listener, authentication, authorization, audit, key custody,
storage composition and operations lifecycle unspecified. Yukh MCP now has an
independent qualified consumer. A real connection would be unsafe and
non-reproducible until one complete server profile closes those remaining
boundaries.

The first profile optimizes for a small, observable staging proof. It does not
reuse relay sessions, add an OAuth deployment, or claim that one-node staging
controls are suitable for production.

## Goals

- expose exactly the five RFC-0015 routes over direct TLS on a private bind;
- bind every request to one short-lived, explicitly provisioned workload token
  and one P-256 DPoP key;
- authorize only the exact five primitives actions for one tenant/principal;
- use the accepted JetStream KV nonce and fenced-lease implementation without
  exposing NATS to the consumer;
- seal lease capabilities through an explicitly provisioned AEAD key;
- durably audit authentication, authorization and operational state without
  storing credentials, proofs, capabilities or request bodies;
- fail readiness closed on trust, clock, storage, audit, epoch or key failure;
- qualify one real TLS nonce/lease lifecycle using synthetic bindings only.

## Non-goals

- public Internet exposure, production use, high availability or failover;
- a relay listener, relay session, transcript route or shared relay audience;
- OAuth discovery, token exchange, refresh, JWKS, bearer fallback or an
  administrative credential-issuance endpoint;
- cloud provisioning, service-account keys, environment credential discovery,
  proxy discovery or workload impersonation;
- provider execution, approval, MCP authorization, protected mutation or live
  apply;
- automatic retry, polling, background reconciliation or credential switching.

## Detailed design

### Topology and process boundary

One Linux process owns one primitives public listener and one operations
listener. Only one active process may use the configured staging profile,
audit database, capability-key set and JetStream KV buckets. Automatic
failover is forbidden.

The public listener binds an exact configured private or loopback IP and
terminates TLS inside the Go process. Its configured public base URI is an
exact `https` origin with no user information, query, fragment or path prefix.
Request `Host`, SNI, `Forwarded` and every `X-Forwarded-*` header are
non-authoritative and cannot change DPoP target normalization. A reverse proxy
is outside this profile.

The only public application routes are:

```text
POST /coordination-primitives/v1/nonces:consume
POST /coordination-primitives/v1/leases:acquire
POST /coordination-primitives/v1/leases:inspect
POST /coordination-primitives/v1/leases:renew
POST /coordination-primitives/v1/leases:release
```

An independent operations listener binds an exact loopback address and exposes
only `GET /livez`, `GET /readyz` and bounded low-cardinality `GET /metrics`.
It exposes no configuration, identity, tenant, scope, capability, storage,
debugging, profiling or administration surface.

### TLS profile

The public listener requires TLS 1.3. Certificate and private-key inputs are
absolute supervisor-owned regular files, not symlinks, and are not writable by
the service account. The process validates that the certificate covers the
exact configured server name or IP and that the key matches before readiness.
It does not enable client-certificate identity in v1.

The staging trust root is private and explicit. Rotation installs an
overlapping server certificate under the same exact public identity, restarts
the single process, and requires a consumer trust-bundle rollout before the old
root is removed. There is no system-root or insecure-verification fallback.
Certificate, key and trust paths never appear in public errors or metrics.

### Workload credential and DPoP profile

The profile admits exactly one configured staging workload identity. An
accountable supervisor generates:

- one uniformly random 256-bit opaque token valid for at most 15 minutes;
- one ephemeral P-256 DPoP key pair valid for no longer than that token;
- one closed public registration containing token digest, public JWK
  thumbprint, tenant, derived principal, issue/expiry time and the five allowed
  actions.

The plaintext token and PKCS#8 private key are delivered only to the consumer
through distinct inherited, already-open file descriptors. They are never
accepted through environment variables, command arguments, repository files,
generic configuration, stdin, named pipes or discovery. The server receives
only the canonical public registration through a supervisor-owned mode-`0440`
regular file. The token digest is domain-separated SHA-256. The private DPoP
key never enters Coordination.

Every request uses:

```http
Authorization: DPoP {opaque-token}
DPoP: {compact ES256 proof}
```

The proof profile is the strict RFC-0010 ES256 shape with exact `htm`, exact
configured public `htu`, integer `iat`, unique `jti` and `ath` over the exact
opaque token. Its public JWK thumbprint must equal the registration. Proof
`iat` may be at most five seconds in the future and 60 seconds in the past.
Proof IDs are reserved durably in a dedicated STRICT SQLite replay database
before authentication succeeds and retained beyond the complete acceptance
window. Reuse across concurrency or restart denies.

This credential is distinct from every relay session and audience. There is no
bootstrap route. Rotation replaces token, key pair and registration as one
accountable staging operation; overlap is forbidden, and expiry immediately
denies new requests. An inability to prove current registration or replay state
makes the service unready.

### Authorization profile

The registration grants only these exact actions:

- `coordination.nonce.consume`;
- `coordination.lease.acquire`;
- `coordination.lease.inspect`;
- `coordination.lease.renew`;
- `coordination.lease.release`.

There are no wildcards, roles, expressions, remote policy calls or per-request
tenant inputs. Authentication returns the registered tenant and principal;
authorization matches the route-derived action and authenticated tenant before
capability or store lookup. An omitted action denies. Authentication and
authorization never grant MCP or protected-provider authority.

The complete canonical registration is signed by one offline Ed25519 staging
policy key. The process receives only the verification key. A malformed,
expired, unsigned, rollback or wrong-profile registration fails readiness; the
last registration is not trusted beyond its expiry.

### Storage, capability sealing and epoch

The service composes only the accepted RFC-0012 JetStream KV adapter. NATS
servers, credentials, account, bucket names, subjects, replicas, restore epoch
and timeouts are exact process configuration and are never caller selected or
returned. Credentials are supplied through one supervisor-owned file
descriptor and held only by the adapter.

The configured positive restore epoch must match both KV buckets and the
primitives service. Mismatch, rollback or restore ambiguity fails readiness.
The service performs no bucket creation in normal start; explicit accountable
bootstrap is a separate reviewed operation.

Lease-capability sealing uses one 256-bit AEAD key delivered through an
inherited supervisor-owned file descriptor. It exists only in locked process
memory where supported, is never written by the process, and is zeroed on
shutdown. The key has a declared ID and validity interval. Rotation retains a
decrypt-only old key for no longer than the maximum lease lifetime. Missing,
ambiguous or overlapping active keys fail readiness. This staging custody is
not a production HSM claim.

### Audit and observability

Authentication allow/deny, authorization allow/deny, registration load,
credential expiry, TLS readiness, epoch validation, key lifecycle, startup,
shutdown and restore fencing are mandatory closed audit operations in a
separate RFC-0011-compatible STRICT SQLite ledger. A decision is not returned
before its required audit append commits. Audit unavailability denies and
makes readiness false.

Audit records contain only closed reason codes, derived identity references,
route action, profile version, decision time and opaque operation/receipt
references. They exclude token/proof bytes and IDs, JWK bodies, lease
capabilities, request/response bodies, scope/value/holder digests, endpoints,
paths, NATS details and arbitrary errors.

Process logs are bounded JSON to stderr with profile, component, outcome and
closed reason only. Metrics have no tenant, principal, route input, token,
digest, capability, endpoint or provider-error labels.

### Bounds, readiness and shutdown

RFC-0015 framing, canonicalization, 4 KiB body and five-second server deadline
remain normative. This profile adds explicit connection, header and idle
timeouts, a fixed maximum concurrent request count, per-principal request
budget and one total request deadline. No layer retries a primitive operation.

Readiness requires valid TLS identity, nonexpired signed registration, current
clock within a five-second rollback fence, open replay/audit databases,
available mandatory audit, exact KV configuration and epoch, available active
AEAD key, and successful dependency probes that disclose no state. Loss of any
gate immediately removes readiness and denies new operations.

Shutdown removes readiness first, stops accepting connections, cancels active
requests at the bounded deadline, closes stores and databases, and zeroes
secret buffers. It never converts an ambiguous operation into success and does
not retry during shutdown.

### Configuration and secret delivery

The executable accepts one absolute non-secret configuration path. The closed
canonical configuration contains profile/version, public and operations binds,
public base URI, non-secret certificate/trust/policy paths, database paths,
public key IDs, epoch and numeric bounds. Unknown members, duplicate keys,
relative paths, unsafe permissions and symlinks fail startup.

Secret descriptors are explicit positive integers passed as a closed
supervisor API at process construction; they are not serialized into the
configuration or logs. The process reads each once, applies an independent
byte bound and closes it. There are no environment overrides or operational
defaults.

## Trust boundaries and threat analysis

The profile adds private-network client to direct TLS, supervisor to process
secret delivery, signed registration to authentication/authorization,
primitives service to JetStream KV, process to audit storage and process to
capability-key custody boundaries.

Primary threats are server impersonation, stolen token replay, DPoP key theft,
proof replay, Host/forwarding substitution, signed-policy rollback, cross-tenant
scope confusion, lease-capability disclosure, KV privilege expansion, restore
epoch rollback, audit omission, secret leakage and ambiguous timeout.

Controls are exact private trust, direct TLS, token-plus-DPoP binding, durable
proof replay reservation, fixed public URI, signed expiring closed registration,
route-derived actions, tenant-derived internal keys, opaque capabilities,
least-privilege KV credentials, epoch fencing, mandatory audit, descriptor-only
secret delivery, bounded calls and no retry.

Residual risks are compromise of the single host or supervisor, plaintext
secret exposure in process memory, private-network denial of service, one-node
availability, staging policy-key compromise and lack of independently witnessed
audit. These risks are accepted only for the explicitly bounded non-production
qualification and cannot be inherited by a production profile.

## Compatibility

The five public routes, request/response schemas and RFC-0021 contention
semantics do not change. The profile adds a process composition and deployment
contract only. Relay APIs, relay sessions and transcript stores remain absent.

The future MCP consumer uses only RFC-0015 bytes plus separately supplied TLS
trust and DPoP material. It imports no Coordination source, package, schema,
client, credential store or deployment code.

## Qualification and authorization sequence

1. Accept this RFC explicitly.
2. Implement the strict configuration, direct TLS/operations listeners,
   registered DPoP authenticator, closed authorizer, replay store, audit adapter,
   capability-key provider and existing KV composition in focused PRs.
3. Qualify hermetically with generated roots, descriptor-delivered synthetic
   secrets, disposable JetStream and restart/ambiguity negative tests.
4. Publish an immutable implementation commit and a redacted deployment plan.
5. Obtain explicit owner approval for provisioning the private staging
   dependencies and ephemeral credential.
6. Provision without sending traffic; review endpoint identity, policy digest,
   trust digest, limits, epoch and rollback plan.
7. Obtain a second explicit approval for one live qualification window.
8. Run only synthetic nonce/lease operations, revoke the credential, remove the
   listener and verify redacted audit plus teardown evidence.

Acceptance of this RFC authorizes steps 2–4 only. Steps 5–8 retain their stated
human gates. Production requires a superseding profile.

Rollback disables the listener, revokes/removes the registration, closes the
consumer trust path and preserves KV terminal/fencing state for accountable
inspection. It never lowers the epoch or deletes nonce/lease history to make a
retry appear safe.

## Alternatives

### Reuse relay sessions

Rejected because RFC-0015 requires a distinct audience and action namespace;
relay transcript admission is not primitives authority.

### Add a local allow-all authenticator

Rejected because private networking and TLS do not establish workload identity
or authorization.

### Use bearer authentication

Rejected because a stolen bearer token would be replayable without possession
of the registered key.

### Put long-lived secrets in environment or configuration

Rejected because they become ambient, inheritable and likely to leak through
diagnostics or process inspection. The staging proof uses short-lived
descriptor-delivered material.

### Start with a public or cloud production profile

Rejected because it combines identity issuance, distributed availability,
cloud IAM, production custody and protected-operation risk before the real
consumer path has been proven.

## Open questions

1. Which supervisor will own descriptor delivery in the first implementation
   environment? The interface is fixed here; selecting systemd or a container
   runtime is an implementation/deployment-plan decision.
2. Which private DNS name or IP and trust root will be provisioned? Exact
   values are deployment evidence and must not enter this public RFC.
