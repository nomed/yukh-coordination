# Session: Strict JOSE and DPoP verifier

- Date: 2026-08-03
- Governing issue: #5
- Accepted decision: RFC-0010
- Branch: `agent/strict-jose-verifier`

## Outcome

Implemented the first RFC-0010 delivery increment as an isolated verification
package. It accepts only the closed external access-token and DPoP profiles,
pre-scans JSON for ambiguity and bounds, verifies signatures with an explicit
algorithm allow-list, derives the stable principal identifier and binds the
external token `cnf.jkt` to the DPoP public key.

The JWKS client has a dedicated TLS transport, no proxy or redirect, bounded
responses, strict public-key metadata, soft and hard cache ages, and throttled
unknown-key refresh. Independent standard-library signatures, negative vectors
and deterministic clocks qualify the boundary.

## Boundary

This increment deliberately adds no identity database, replay persistence,
session capability lifecycle, audit port, runtime configuration or executable.
Those remain separate reviewable increments in the RFC-0010 delivery sequence.

## Evidence

- `go test -race ./...` with a real NATS JetStream server;
- `go vet ./...`;
- both JOSE pre-scan fuzz targets;
- `govulncheck ./...` with Go 1.26.5: no called vulnerabilities;
- exact `github.com/go-jose/go-jose/v4` dependency at `v4.1.4`.
