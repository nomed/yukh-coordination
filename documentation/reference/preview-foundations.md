# RFC-0025 local foundations

The RFC-0025 implementation foundation is deliberately pure and local. It
defines contracts for a future hermetic qualification; it does not assemble,
start or authorize a preview runtime.

## Public schemas

- `suite-preview-run-manifest-1.schema.json` closes the non-secret run input:
  exact source, tree, corpus and component artifact digests; logical component
  identities and profile versions; a maximum lifetime of four hours; resource
  bounds; and whole-sandbox teardown.
- `suite-preview-authority-1.schema.json` closes the Effect A and Effect B
  nonce-scope projections, pre-lease projections and final bindings. Effect A
  uses two fixed absence markers. Effect B carries exact MCP definition,
  implementation and producer digests.
- `suite-preview-public-evidence-1.schema.json` exposes outcome classes and
  designated public digests only. It has no field for tokens, credentials, raw
  nonce values, lease capabilities, bindings, approvals, provider bodies,
  transcripts or private topology.

The Go package `internal/previewprofile` requires canonical JSON for run
manifests and public evidence, rejects unknown members, and applies stricter
semantic validation after schema validation.

## Authority derivation

Effect A and Effect B use the exact domain strings fixed by RFC-0025. The
nonce-scope digest is derived before pre-lease projection. Lease resource and
holder identities are then derived from that closed projection. The nonce
value is derived only from the complete final binding.

The frozen fixture
`schema/test-vectors/suite-preview-rfc-0025-1.json` records both effects'
canonical bytes and every derived digest. Its negative cases reject
cross-effect authority reuse, restore-epoch substitution and a changed scope
that retains an approved nonce value. The changed-scope case records zero
service calls and zero consumed outcomes.

## Teardown and evidence

The pure teardown state machine permits only the next RFC-0025 transition:

`requested` → `admission_closed` → `evidence_frozen` →
`credentials_revoked` → `processes_stopped` → `storage_removed` →
`absence_verified` → `completed`.

Failure or ambiguity before completion moves to `teardown_incomplete`.
Terminal states cannot be advanced or rewritten.

Public evidence is built from typed allowlisted values rather than unrestricted
output followed by redaction. Adversarial tests inject secret, raw nonce, lease,
binding, approval and provider-response fields and require rejection.

## Explicit non-capabilities

This foundation contains no relay binary, NATS or Docker process,
infrastructure, credential generation, network access, live provider,
protected effect, runtime activation or readiness claim. Those remain outside
the accepted implementation boundary and require separate authorization and
independent review.
