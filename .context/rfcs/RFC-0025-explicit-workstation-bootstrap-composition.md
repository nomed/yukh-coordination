# RFC-0025: Explicit workstation bootstrap composition

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-05
- Governing issue: #6
- Governing architecture: RFC-0013, RFC-0014 and RFC-0018

This RFC does not authorize credentials, service configuration, external
traffic, deployment, user-data migration or live-session bootstrap.

The project owner explicitly accepted this RFC on 2026-08-05. Acceptance
authorizes only the separately reviewed implementation and qualification
increments described below.

## Decision requested

Authorize a separately reviewable Linux workstation composition named
`linux-secret-service-v1` for the RFC-0013 `session bootstrap` command. The
composition binds exactly one RFC-0018 Secret Service root-key adapter, one
encrypted local-custody SQLite database, one caller-owned external-token file
descriptor, and one explicit HTTPS relay URI.

The command is a client of the existing relay contract. It creates no relay
server, discovers no provider, grants no execution authority and never treats
local custody state as coordination authority.

## Closed command and configuration boundary

The command accepts:

```text
yukh-coordination session bootstrap \
  --config ABSOLUTE_CONFIG_PATH \
  --token-fd DECIMAL_FD \
  --bus-fd DECIMAL_FD
```

`--config` names one explicit, private, regular configuration file. It contains
only non-secret, closed values:

- profile identifier;
- absolute local-custody SQLite path;
- exact HTTPS relay base URI;
- fixed Secret Service name, collection object path and root-item schema;
- bounded connection, request and total-operation deadlines.

The configuration parser rejects unknown fields, duplicate fields, symlinks,
non-private files and directories, relative paths, embedded credentials,
query/fragment relay URIs and mutable aliases.

`--token-fd` is a caller-owned read-only descriptor carrying one bounded
external DPoP-bound access token. The CLI reads it once, closes no descriptor
it does not own, does not name it in output and does not use command arguments,
environment variables, files, standard input, logs, Action outputs or shell
history for token material.

`--bus-fd` is a caller-owned connected Unix-domain D-Bus stream. The CLI does
not read `DBUS_SESSION_BUS_ADDRESS`, resolve a bus address, inspect runtime
directories, invoke desktop discovery or open a default bus. The Secret
Service adapter accepts only the configured service, collection and item
schema. It refuses prompts, locked collections, ambiguous lookup, plaintext
transfer fallback and alternate collections.

The executable does not auto-select this profile. `linux-secret-service-v1`
is the only accepted profile spelling for this increment; any other profile or
any omitted required input fails before custody, token parsing or network I/O.

## Bootstrap sequence

After parsing all closed inputs, the command:

1. constructs the RFC-0018 root-key adapter on the supplied bus connection;
2. opens the private encrypted SQLite store with that adapter;
3. provisions or resolves the exact profile P-256 signer;
4. reads and validates the bounded external token from `--token-fd`;
5. invokes the RFC-0009 HTTPS bootstrap exchange with the signer-bound DPoP
   proof and exact configured relay URI;
6. persists and reloads the proof-bound session through exact CAS; and
7. emits only the RFC-0013 closed success or stable error result.

Any failure is fail-closed. Before a relay response, RFC-0014 bounded cleanup
may retire only a signer created by this attempt. After an ambiguous or
successful relay response, the signer remains; the client never reports
success unless exact local reload/open/thumbprint validation completes.

The CLI does not add a background renewal loop, session sharing, root-key
rotation, revocation claim, relay redirect handling, proxy identity, fallback
profile or write-back of any token/session to the external authority.

## Authority and security boundary

The caller providing descriptors remains responsible for the external identity,
the D-Bus connection and descriptor lifetime. That identity is not inferred to
be the Yukh participant; the relay issues the participant identity and session
epoch. The custody profile protects local session material but neither grants
work ownership nor resolves claim conflicts.

No user prompt is permitted. A locked Secret Service collection, malformed
descriptor, changed root item, invalid DPoP binding, redirect, relay failure,
store conflict or uncertain commit produces a bounded failure. Errors, JSON
output and traces exclude tokens, proof bytes, root-key material, D-Bus
addresses, collection/item identifiers, database paths and raw provider
bodies.

## Qualification

Acceptance requires implementation tests that prove:

- unknown, duplicate, ambient and permissive configuration is rejected before
  token, D-Bus or network access;
- only supplied descriptors are used, and neither token nor D-Bus discovery
  reads ambient environment or standard input;
- Secret Service zero/one/multiple, locked and prompt outcomes satisfy
  RFC-0018 without plaintext fallback;
- the exact configured relay target, method and DPoP binding reach the HTTPS
  issuer, while redirects and alternate authorities do not;
- successful bootstrap persists and reloads the exact signer binding, and all
  partial/ambiguous failures report no usable session;
- output uses stable RFC-0013 JSON/exit codes and redacts every secret and
  provider-specific identifier; and
- two isolated executable processes with distinct profiles complete the
  existing RFC-0013 qualification without copying user-mediated credentials or
  session state.

Real Secret Service evidence for GNOME Keyring and KeePassXC remains required
by RFC-0018 before that adapter is qualified for a supported workstation.

## Compatibility, migration and rollback

This introduces one opt-in command composition and does not change relay,
event, receipt, custody-port or configuration contracts for existing clients.
Existing local records are usable only when their exact root item, profile and
signer binding already match; no import, discovery or migration is implied.

Rollback removes the composition from the executable. It does not delete the
Secret Service item, encrypted database, signer or relay session, and does not
claim remote revocation. A separately accepted record is required for
rotation, recovery, migration or deletion workflows.

## Alternatives rejected

- Default D-Bus or desktop discovery violates RFC-0018's caller-owned
  connection boundary.
- Environment variables, command-line token values and plaintext files expose
  bootstrap credentials.
- An automatic local fallback changes custody guarantees during failure.
- A shared profile or copied database erases distinct participant attribution.
- Executable wiring without the configuration and descriptor boundary leaves
  the root-identity authority undefined.
