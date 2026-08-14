# RFC-0029: macOS legacy Keychain query compatibility

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-05
- Governing issue: #6
- Governing architecture: RFC-0014, RFC-0027 and RFC-0028

The project owner explicitly accepted this RFC on 2026-08-05. Acceptance
authorizes only the compatibility correction and qualification described here.

## Correction requested

RFC-0028's explicit file reference remains the sole Keychain selection
mechanism. For that legacy Keychain scope, the native lookup must use an exact
one-element `kSecMatchSearchList` and request at most two matches. Two matches
are sufficient to distinguish the required one item from every ambiguous
cardinality, while `kSecMatchLimitAll` returns `errSecParam` (`-50`) on the
qualified macOS legacy-file implementation.

The item is protected by the caller-created Keychain file while that exact file
is unlocked. The native adapter must not set or expect `kSecAttrAccessible`:
legacy file Keychains do not expose that Data Protection Keychain attribute.
The configuration access group is consequently required to be empty: a
nonempty access group is a Data Protection Keychain attribute and fails closed.
The adapter continues to require the exact generic-password class, service,
account, label and 32-byte nonzero secret, with authentication UI disabled.

No Data Protection, Login or default Keychain is selected, queried, modified
or used as a fallback. The adapter opens only the configured private file and
the lookup search-list has exactly that reference.

## Qualification

The opt-in native qualification creates, unlocks, writes and reopens only a
random disposable legacy Keychain file. It verifies the exact root item
creation/reopen path and cleanup deletes that item and file. No production
Keychain or global Keychain store participates.

## Compatibility

This corrects unreleased macOS profile behavior only. It does not import,
modify or delete pre-existing Keychain items, and it authorizes no migration.
