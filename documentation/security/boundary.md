# Security boundary

Treat event content, evidence references, client time and display names as
untrusted. The relay must authenticate, authorize, validate and durably append
before acknowledging a statement.

The relay never fetches evidence URLs and never stores adopter execution
credentials. Missing history, invalid receipts, ambiguous identity or uncertain
storage produce a non-final result or fail closed.

The [RFC-0025 local foundations](../reference/preview-foundations.md) add only
closed schemas and pure validators. Public preview evidence is structurally
allowlisted and has no raw nonce, lease capability, complete binding,
credential, provider body, transcript or private-topology field. The
foundation does not start a relay, broker, container, network or provider
operation.

The repository [threat model](https://github.com/nomed/yukh-coordination/blob/main/.context/security/threat-model.md)
remains authoritative. Security disclosures use the private channel described
in [SECURITY.md](https://github.com/nomed/yukh-coordination/blob/main/SECURITY.md).
