# Identity boundary

This directory contains the first two isolated increments of accepted
RFC-0010. The root package owns strict JWT/JWKS and RFC 9449 DPoP verification
plus the closed identity lifecycle types. The `sqlite` subpackage owns the
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

The directory still has no audit implementation, session-token generator,
provider composition, HTTP wiring or process configuration. A cryptographically
valid proof and a registry transaction are therefore not yet a complete
admitted request.
