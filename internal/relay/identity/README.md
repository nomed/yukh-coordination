# Identity verification

This package implements the verification-only increment of accepted RFC-0010.
It validates the strict external JWT/JWKS profile and RFC 9449 DPoP proofs but
does not issue or persist a relay session.

The boundary is intentionally layered:

- compact JWS framing and decoded JSON are bounded before JOSE parsing;
- duplicate and case-colliding member names are rejected recursively;
- JWT and DPoP headers and claims use closed profiles;
- `go-jose` receives explicit asymmetric algorithm allow-lists and keys;
- JWKS comes only from the configured HTTPS URL through a dedicated bounded
  client with no redirects, proxy, compression or discovery;
- DPoP signatures are checked before claims are trusted, and `ath`, public URI,
  method, time and JWK thumbprint are verified explicitly.

The package has no SQLite schema, proof replay state, audit implementation,
session-token generator, revocation scheduler or process configuration. Those
remain later RFC-0010 increments. A cryptographically valid proof is therefore
not yet a complete admitted request.
