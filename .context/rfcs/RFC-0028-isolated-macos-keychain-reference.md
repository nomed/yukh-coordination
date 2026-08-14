# RFC-0028: Isolated macOS Keychain reference

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-05
- Governing issue: #6
- Governing architecture: RFC-0014 and RFC-0027

The project owner explicitly accepted this RFC on 2026-08-05. It supersedes
only RFC-0027's macOS Keychain selection boundary.

## Decision

`macos-keychain-v1` must receive one explicit Keychain reference in its closed
configuration. It must not use the Data Protection Keychain global store, the
Login Keychain, a default keychain, or a mutable search list.

The reference identifies a caller-created, private Keychain file. The adapter
opens that exact file, verifies it is a regular private file owned by the
effective user and uses a one-element Keychain query scope containing only that
reference. This is an exact resource binding, not discovery or a fallback
search list.

The Keychain reference is public configuration metadata but is redacted from
ordinary formatting and error output. It contains no token, root key,
participant, tenant or relay credential.

## Qualification

Native qualification creates a temporary Keychain file with a random test
password, passes its exact reference to the adapter, verifies creation and
reopen of one root item, then deletes the item and temporary Keychain. It must
not read, add to, delete from or select the Login Keychain or Data Protection
Keychain.

Failure to open, unlock, verify or scope the exact Keychain fails closed. The
adapter never falls back to another Keychain.

## Compatibility

This is an unreleased profile correction. Existing global Data Protection
Keychain items created by earlier development builds are not imported or
opened. They require explicit human cleanup; no automated migration or
deletion is authorized.
