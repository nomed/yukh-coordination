# Identity boundary

This directory contains the three isolated implementation increments of
accepted RFC-0010. The root package owns strict JWT/JWKS and RFC 9449 DPoP
verification, the closed identity lifecycle and audit types, and the provider
that implements the RFC-0009 HTTP ports. The `sqlite` subpackage owns the
separate durable identity registry.

The boundary is intentionally layered:

- compact JWS framing and decoded JSON are bounded before JOSE parsing;
- duplicate and case-colliding member names are rejected recursively;
- JWT and DPoP headers and claims use closed profiles;
- `go-jose` receives explicit asymmetric algorithm allow-lists and keys;
- JWKS comes only from the configured HTTPS URL through a dedicated bounded
  client with no redirects, proxy, compression or discovery;
- DPoP signatures are checked before claims are trusted, and `ath`, public URI,
  method, time and JWK thumbprint are verified explicitly.

The provider generates opaque session tokens, but this directory does not own
their audit storage, checkpoint signing, policy, process wiring or external
configuration. The mandatory `Auditor` remains a port. RFC-0011 step 1 supplies
a durable adapter under `internal/relay/audit/sqlite`, but production
composition cannot claim audit readiness until the later checkpoint, recovery
and explicit wiring increments are qualified.
