# Session: RFC-0011 audit coverage and composition step 5

- Date: 2026-08-03
- Governing issue: #37
- Pull request: #47
- Accepted decision: RFC-0011
- Scope: delivery step 5 only

## Outcome

Completed the five-step RFC-0011 implementation sequence. The canonical audit
vocabulary now includes revocation, JWKS refresh, restore fencing, checkpoint
commit and verification-key lifecycle, with deterministic JCS vectors for each
closed shape.

JWKS initialization and refresh fail closed unless the result is durably
audited, binding a configured authority reference and the exact returned set
digest. Revocation uses one caller-owned UUIDv7 operation ID persisted by
identity schema v2; exact retries are idempotent, while replacement operations
conflict. The provider does not report revocation success before audit
completion.

Verification-key statements and their lifecycle records commit atomically in
the audit ledger. Checkpoint creation avoids self-reference: it precomputes the
closed checkpoint record, obtains a signature over the tree that includes that
record, then commits record and checkpoint together only if the head is still
exact. Startup verifies lifecycle coverage and the checkpoint record at every
signed tree head.

Restore is an explicit monotonic saga rather than a claimed cross-database
transaction. Identity floors are staged while fenced; Audit atomically appends
the manifest-bound `restore_fence` record, persists the signed manifest and
admits its ledger; only then does Identity consume that exact receipt and admit
authentication. Every stage is repeatable after a crash. Recovery snapshots
include the maximum of live epochs and prior restore floors, preventing later
backup regression.

The runtime-facing audit provider always executes strong operational readiness.
The runtime requires readiness on its bootstrap security provider and checks it
before serving or announcing readiness, with bounded reverse-order cleanup on
failure.

## Qualification

- deterministic corpus: 62 fixtures and 18 canonical vectors;
- three fixed Ed25519 signatures independently verified by OpenSSL;
- standards-schema and cross-runtime gates passed;
- JavaScript: 14 tests passed;
- full Go suite and race detector passed with NATS Server 2.12.0;
- `go vet ./...` passed;
- `govulncheck ./...` reported no reachable vulnerabilities;
- repository structure and generated-manifest gates passed.

Negative and restart tests cover closed operation matrices, inapplicable fields,
JWKS audit ordering, revocation replacement, key/checkpoint atomic coverage,
checkpoint head races, staged identity admission, manifest-bound audit
completion, crash-resume ordering, readiness failure and epoch-floor carryover.

## Explicit boundary

This increment adds no executable, public administration API, Vault client,
private key, credential source or deployment configuration. It does not claim
atomicity across SQLite files or production readiness for an unspecified
topology. RFC-0012 and the concurrent JetStream KV adapter PR #46 are untouched.

## Next step

Explicit owner acceptance may promote and merge #47, completing RFC-0011 and
allowing issue #37 to close. The repository must then reconcile against the
independent #46 outcome rather than opening duplicate JetStream KV work. A new
component increment requires its own governing issue and reviewable pull
request.
