# Session: Session bootstrap contract review

- Date: 2026-08-03
- Governing issue: #5
- Proposed decision: RFC-0009
- Branch: `agent/session-bootstrap-contract`

## Outcome

Proposed the public session bootstrap and request-aware authentication contract
for the accepted single-node process profile.

The review separates external principal bootstrap from ordinary relay-session
authentication. It gives each trust domain a dedicated port, replaces the
unshipped Bearer resource posture with DPoP, and restricts providers to closed
authentication material rather than raw HTTP requests.

## Boundary

This session changes documentation only. It introduces no handler route, Go
port, JWT/DPoP dependency, identity database, provider, configuration schema or
binary. Owner acceptance is required before the contract implementation.

## Qualification plan

The implementation increment will revise `httpapi` and runtime composition
with deterministic fakes and negative boundary tests. Cryptographic and
persistence qualification remains reserved for the subsequent provider
increment.
