# Session: Identity provider and mandatory audit composition

- Date: 2026-08-03
- Governing issue: #5
- Accepted decisions: RFC-0009 and RFC-0010
- Branch: `agent/identity-provider-composition`

## Outcome

Implemented the third RFC-0010 increment as the concrete implementation of
the RFC-0009 bootstrap and resource-authentication ports. Bootstrap now orders
strict external verification, bounded session material generation, atomic
pending reservation, mandatory allow audit and exact activation before the
plaintext token can leave the provider. Resource authentication orders proof
verification, active-session lookup plus replay commit, mandatory allow audit
and only then returns the admitted identity.

All invalid and unavailable paths produce closed audit records without token,
proof, JWT, JWK or arbitrary provider text. A missing denial audit changes a
public denial to temporary unavailability. An allow-audit outage after resource
reservation consumes the proof and admits no request. Readiness requires a
non-stale verifier, admitted registry and ready auditor.

## Boundary

The new `Auditor` is a mandatory port, not an audit-store implementation. This
increment adds no audit database, hash chain, checkpoint signer, policy engine,
configuration schema, listener or executable. Runtime retains explicit
dependency injection and has no test or bearer fallback.

## Evidence

- deterministic ordering tests cover pending, audit and activation;
- denial-audit and allow-audit outages remain non-oracular;
- activation uncertainty creates no replacement session;
- session-material collisions are bounded and security-audited;
- replay is consumed before an unavailable allow audit;
- a real HTTP integration signs JWT and DPoP independently, uses the real
  verifier and SQLite registry, admits one session request and rejects proof
  reuse;
- full race and JetStream qualification, vet and vulnerability scanning are
  required before publication.
