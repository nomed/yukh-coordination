# Session: Identity and DPoP provider review

- Date: 2026-08-03
- Governing issues: #3 and #5
- Accepted decision: RFC-0010
- Pull request: #33
- Branch: `agent/identity-dpop-provider-rfc`

## Outcome

Accepted the complete identity-provider profile for the accepted single-node
runtime. The design closes external JWT/JWKS validation, strict DPoP proof
verification, persistent replay protection, opaque relay sessions, epoch
allocation, revocation, clock rollback and restore fencing.

The review identified two boundaries that cannot be solved by naming them
atomic. Identity and security audit remain separate WAL databases, so bootstrap
uses an explicit pending/audit/active state machine and reveals no token before
activation. An identity backup also cannot prove epochs committed after its
capture, so restored admission requires an external signed epoch checkpoint.

## Boundary

This session changes documentation only. It adds no JOSE dependency, JWKS
client, SQLite schema, audit port, provider, configuration or executable. The
first authorized implementation increment is the strict JOSE verifier.

## Proposed delivery

1. strict JWT/JWKS and DPoP verifier;
2. SQLite identity and lifecycle registry;
3. RFC-0009 provider composition with mandatory audit port.
