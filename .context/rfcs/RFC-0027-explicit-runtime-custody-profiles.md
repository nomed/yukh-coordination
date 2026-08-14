# RFC-0027: Explicit runtime custody profiles

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-05
- Governing issue: #6
- Governing architecture: RFC-0013, RFC-0014, RFC-0018, RFC-0020 and RFC-0026

This RFC does not authorize credentials, external traffic, deployment or
migration of existing custody records.

The project owner explicitly accepted this RFC on 2026-08-05. Acceptance
authorizes only the separately reviewed implementation and qualification
increments described below.

## Decision requested

Define one explicit custody profile for each supported runtime class, so the
client can operate on the platform where it runs without weakening its
credential, signer or authority boundary:

| Runtime | Profile | Root/custody boundary |
| --- | --- | --- |
| Linux interactive workstation | `linux-secret-service-v1` | Freedesktop Secret Service plus encrypted local SQLite, per RFC-0018 and RFC-0026 |
| macOS interactive workstation | `macos-keychain-v1` | Keychain Services item plus encrypted local SQLite |
| Headless Google Cloud workload | `gcp-workload-v1` | Explicit Workload Identity, Cloud Storage and Cloud KMS, per RFC-0020 |

The profile is always selected by closed configuration. The executable does
not infer it from `GOOS`, desktop services, environment variables, credential
availability, metadata services or a fallback chain. An unsupported runtime or
profile fails closed before custody, token or network access.

## macOS Keychain profile

`macos-keychain-v1` is a separately implemented composition for interactive
macOS workstations. One exact Keychain generic-password item contains the
32-byte random root key; an absolute private local SQLite database persists
only RFC-0014 encrypted session and signer records.

Its configuration contains only an opaque profile identifier, private database
path, exact Keychain access-group/service/account schema, exact HTTPS relay
base URI and bounded deadlines. It contains no token, key bytes, repository,
tenant, user or endpoint credentials.

The adapter must use only the configured Keychain item query. It rejects zero
or multiple matching items according to the same creation/reconciliation rules
as RFC-0018, mismatched item attributes, unexpected accessibility class,
interactive authorization, UI prompts, keychain search-list/default-keychain
selection, file fallback and ambient identity discovery.

The external DPoP-bound token remains a caller-owned descriptor input. The
Keychain item protects local root material only; it is not an identity provider
and does not establish relay participant identity.

## Shared command boundary

`session bootstrap` retains RFC-0026's closed descriptor and configuration
model. A profile-specific runtime factory is chosen from the named
configuration profile only. Each factory must provide exactly one credential
store, proof-signer store, external-token source and direct HTTPS issuer. No
profile may substitute another when a configured store is locked, unavailable
or unsupported.

The relay remains authoritative for external-token authentication, participant
identity, session epoch, transcript state and receipts. Local profile selection
does not grant work ownership or execution authority.

## Qualification

Acceptance requires:

- deterministic profile-selection tests that reject omitted, unknown,
  environment-inferred and fallback profile choices;
- native macOS Keychain tests for exact item selection, zero/one/multiple
  outcomes, lock/authorization/UI rejection, strict root-item shape and
  redaction;
- encrypted SQLite/session/signer CAS and key-binding tests shared with
  RFC-0018;
- native macOS integration evidence on supported macOS versions; and
- retained GNOME Keyring and KeePassXC evidence for the separate Linux
  profile.

## Compatibility and migration

Existing `linux-secret-service-v1` and `gcp-workload-v1` records remain
independent. A profile never imports, copies or opens another profile's root
item, database, signer or session record. Cross-platform migration, root-key
rotation, backup and session transfer require separate accepted records.

## Alternatives rejected

- One universal local profile would require pretending Keychain, Secret
  Service and cloud KMS have equivalent identity and custody semantics.
- Automatic OS detection makes the security boundary depend on ambient
  machine state and creates downgrade paths.
- A plaintext local fallback defeats custody precisely when the platform
  provider is unavailable.
