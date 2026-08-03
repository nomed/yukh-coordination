# RFC-0007: Relay composition and lifecycle boundary

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #5
- Governing architecture: RFC-0002, RFC-0003, RFC-0004, RFC-0005 and RFC-0006

## Decision requested

Freeze the composition and lifecycle boundary that turns the qualified relay
layers into one runnable service without inventing permissive identity,
authorization, signing or administration providers.

Acceptance authorizes an internal composition package and executable lifecycle
tests. It does not authorize a public binary, deployment, production operation,
an authentication scheme, an ACL store, a signing-key source or an
administrative control plane.

The project owner accepted this boundary on 2026-08-03 after review in PR #28.

## Core decision

The first composition root lives at `internal/relay/runtime`. It assembles the
existing HTTP/SSE handler, application service, append service, Store and
subscription source from explicit dependencies supplied by its caller.

It owns lifecycle, not policy. It must not:

- implement authentication, authorization, signing or channel administration;
- read environment variables, flags, secret files or remote configuration;
- select an adapter from a string;
- create an insecure development identity or allow-all policy;
- expose persistence, NATS or Matrix concepts through the public HTTP contract.

The repository does not add `cmd/` in this increment. A process binary becomes
honest only after a separate accepted provider profile names how authenticated
session identity, ACL decisions, channel provisioning and signing keys are
obtained. At that point the accepted profile may authorize `cmd/` as a new
top-level responsibility and translate external configuration into the typed
runtime dependencies.

## Typed composition contract

Construction requires a closed dependency set:

- `relay.Store`;
- the application `SubscriptionSource`;
- `httpapi.Authenticator`;
- `httpapi.Authorizer`;
- `service.Signer`;
- protocol validator;
- an already-bound `net.Listener`;
- explicit HTTP/SSE timing limits;
- an ordered set of uniquely named owned resource closers;
- an explicit graceful-shutdown deadline.

The runtime rejects nil dependencies, invalid limits and duplicate resource
names. Listener creation and TLS material remain outside the internal package
so tests can use an in-memory or loopback listener without teaching the core
about certificate files or proxies. RFC-0004 per-request TLS enforcement stays
active; a future process profile must additionally prove how the listener is
protected before it can be operated.

Construction performs no goroutine start and acquires no hidden resource.
`Run(context.Context)` is the only lifecycle entry point and may be called
once. A failed construction or startup leaves no HTTP handler serving traffic;
listener ownership is transferred only by successful construction.

## Adapter compositions

The composition contract supports exactly the already-qualified pairings:

- SQLite Store plus the process-local `service.LiveChanges` source;
- JetStream Store plus the same JetStream instance as subscription source.

The runtime package does not name either implementation. The caller constructs
and owns the selected adapter, then transfers explicitly listed close
responsibilities to the runtime. The JetStream Store does not own the NATS
connection; a caller that creates the connection must register that connection
for shutdown. SQLite owns its database handle and must likewise be closed once.

Mixing a JetStream Store with process-local notifications is invalid for a
distributed runtime profile. This constraint is enforced by the future
provider/profile composition, not by reflection or product checks in the
neutral runtime.

Matrix is a client of the public HTTP/SSE contract and can never be injected as
a Store, subscription source or lifecycle dependency of the relay process.

## Lifecycle state machine

The observable internal lifecycle is monotonic:

```text
constructed → starting → ready → draining → stopped
                      ↘ failed ↗
```

`ready` means all supplied dependencies were constructed successfully and the
HTTP serving goroutine has started on the supplied listener. It is not a
production readiness claim. The package exposes readiness and terminal
completion through in-process signals for tests and a future process wrapper;
it adds no route to the RFC-0004 public API.

`Run` returns when the parent context is cancelled, serving fails, or shutdown
completes. A second `Run` call fails deterministically.

## Shutdown order

On cancellation or serving failure the runtime:

1. enters `draining` exactly once;
2. cancels the server base context, which cancels every request context and
   terminates live streams;
3. calls `http.Server.Shutdown` with the explicit deadline, stopping new
   acceptance while allowing bounded commands already completing to drain;
4. forces `http.Server.Close` if graceful shutdown exceeds the deadline;
5. closes owned resources once, in reverse registration order;
6. enters `stopped`, or `failed` if serving, shutdown or close produced an
   error;
7. returns a joined, redacted error that preserves every lifecycle failure.

Resource close errors never suppress an earlier serving error. Panic recovery,
automatic restart and retry loops do not belong in the runtime; a process
supervisor owns restart policy.

## Failure and security posture

Startup and lifecycle fail closed:

- no listener is served when any required dependency is absent;
- no fallback Store, signer, authenticator or authorizer exists;
- no secret value, bearer token, event body, authorization binding or private
  key material appears in lifecycle errors;
- public HTTP routes remain exactly those accepted by RFC-0004;
- health, metrics, profiling and administration require a separately bound
  operational surface and a future decision;
- storage, authentication, authorization and signing uncertainty continue to
  use the existing application failure semantics.

The runtime does not claim that dependency construction proves dependency
health. Provider-specific startup probes, credential refresh, key rotation,
policy reload and outage behavior belong to their provider profiles.

## Qualification evidence

Implementation acceptance requires tests that prove:

- construction rejects every missing dependency and invalid lifecycle limit;
- no HTTP handler runs before `Run` and readiness follows launch of serving;
- a real HTTP request traverses handler, application, signer and Store through
  injected qualified fakes or adapters;
- cancellation stops acceptance, terminates SSE and closes resources once in
  reverse order;
- a blocked request is force-closed at the shutdown deadline;
- an HTTP serving failure initiates the same cleanup path;
- concurrent cancellation and serving failure do not double-close resources;
- multiple `Run` calls fail deterministically;
- joined errors retain serve, shutdown and close failures without sensitive
  material;
- the repository structure check continues to reject an unapproved `cmd/`
  directory.

These are lifecycle qualification claims only. They do not qualify any real
provider or deployment.

## Provider profile required before a binary

A later RFC must select and threat-model, at minimum:

1. authenticated session bootstrap and the source of relay-issued participant
   instance/session epoch bindings;
2. bearer-token validation, issuer/audience and revocation behavior;
3. ACL policy storage, decision receipt creation and revocation signalling;
4. channel registration and finite-retention provisioning;
5. signing-key selection, custody, rotation and recovery;
6. listener/TLS termination and trusted network boundary;
7. SQLite or JetStream external configuration and credential delivery;
8. operational health, audit and metrics exposure.

No `--insecure`, allow-all, static universal token or database-local signing
key shortcut may satisfy this gate.

## Compatibility

This decision adds no protocol field, route, media type, cursor, command or
adapter configuration. Existing packages retain their current interfaces. The
composition package is internal and carries no external Go compatibility
promise.

## Rollout and rollback

Implementation is one focused repository increment behind tests. It can be
removed without data migration because it owns no stored representation and
introduces no executable or deployment configuration.

## Alternatives rejected

### Add a binary with fake providers now

Rejected because a service that accepts an arbitrary token, authorizes every
channel or signs from the event database contradicts RFC-0002 while looking
more complete than it is.

### Put environment and adapter selection in the runtime package

Rejected because it couples lifecycle mechanics to one deployment profile and
makes secret/configuration policy an implicit core concern.

### Let each adapter build its own HTTP server

Rejected because it duplicates admission and shutdown behavior and lets a
persistence product become the application composition root.

### Add public health routes to the existing handler

Rejected because RFC-0004 defines a closed public edge. An operational surface
has different authentication, disclosure and availability requirements.

### Embed Matrix in the process

Rejected because RFC-0003 makes Matrix a later client bridge, not relay
infrastructure or persistence.

## Open questions deliberately deferred

- provider and deployment profile;
- operational listener routes and authentication;
- process packaging and image construction;
- supervisor and restart policy;
- production topology and readiness criteria.
