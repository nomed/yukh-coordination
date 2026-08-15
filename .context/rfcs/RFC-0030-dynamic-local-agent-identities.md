# RFC-0030: Dynamic local agent identities

- Status: Accepted
- Authors: Nomed with Codex implementation support
- Created: 2026-08-15
- Accepted: 2026-08-15
- Decider: project owner
- Governing issue: #224
- Depends on: RFC-0014, RFC-0025

## Decision

Replace the local preview's fixed `agent-a` and `agent-b` allowlist with bounded,
validated agent identities provisioned on demand. This is a local qualification
profile and does not change the neutral public Coordination protocol.

An agent name is `agent-` followed by a lowercase slug. Each name receives a
distinct root key, custody database, client configuration, principal,
participant instance and session. The supervisor issues an external token only
for a syntactically valid local agent name and never accepts a caller-supplied
principal or participant binding.

The launcher creates missing local custody/configuration atomically from the
supervisor's authenticated public metadata. Existing identities are reused;
unknown files, symlinks, unsafe permissions and invalid names fail closed.

## Team relationship

Parent, role, task and team membership remain Coordination event data owned by
the team control plane. They do not grant authentication or authorization. A
child is a full participant with its own identity, not an alias or subprocess
reported as its parent.

## Bounds and lifecycle

The local profile supports at most 32 active identities per runtime directory,
names of at most 48 characters and the existing preview lifetime. Provisioning
is serialized per identity. Explicit removal belongs to a later lifecycle
increment; whole-preview teardown remains the current destructive boundary.

## Security impact

Dynamic names increase local denial-of-service and storage-exhaustion risk. The
closed name grammar, identity count, per-identity custody separation, fixed
tenant/channel, authenticated supervisor and no caller-selected claims bound
that risk. Authentication still grants only the existing preview publish and
replay actions.

## Qualification

Tests must cover three independently bootstrapped identities, invalid names,
identity-count exhaustion, distinct custody/config paths, token substitution,
replay agreement and unchanged two-agent compatibility.

## Rollback

Restore the two-name allowlist and remove dynamically created local identity
files after stopping the preview. Transcript records require no migration.
