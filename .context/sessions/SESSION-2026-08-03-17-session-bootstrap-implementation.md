# Session: Session bootstrap contract implementation

- Date: 2026-08-03
- Governing issue: #5
- Governing decision: RFC-0009
- Branch: `agent/session-bootstrap-implementation`

## Outcome

Implemented the accepted transport and composition contract for relay session
bootstrap and request-aware authentication.

The HTTP edge now exposes `POST /coordination/v1/sessions`, requires DPoP
authorization and proof framing on every authenticated route, constructs proof
targets only from the configured public HTTPS base URI, and emits the closed
canonical session response. External bootstrap and relay-session admission use
separate provider ports and separate opaque material types.

Runtime construction now requires an explicit bootstrap provider and public
base URI. There is no compatibility fallback to Bearer authentication.

## Evidence

- deterministic bootstrap success bytes and response headers;
- bootstrap framing rejection before provider invocation;
- malformed, duplicate and oversized DPoP material rejection;
- hostile Host and forwarded-header isolation;
- bootstrap/resource trust-domain separation;
- redacted ordinary and Go-syntax formatting;
- malformed provider success and unknown provider failure sanitization;
- runtime dependency rejection;
- complete local Go test, vet and race/JetStream qualification suites.

## Boundary

The increment adds no JWT parser, DPoP cryptographic verifier, token generator,
identity database, security-audit store, configuration file schema, listener or
process binary. Test doubles prove orchestration only and make no cryptographic
qualification claim.

## Next gate

After merge, RFC-0008 permits a focused identity-provider design covering RFC
9068 validation, DPoP verification, atomic SQLite session creation, replay
state, epochs and revocation. That design requires owner review before provider
implementation.
