# Security boundary

Treat event content, evidence references, client time and display names as
untrusted. The relay must authenticate, authorize, validate and durably append
before acknowledging a statement.

The relay never fetches evidence URLs and never stores adopter execution
credentials. Missing history, invalid receipts, ambiguous identity or uncertain
storage produce a non-final result or fail closed.

The repository [threat model](https://github.com/nomed/yukh-coordination/blob/main/.context/security/threat-model.md)
remains authoritative. Security disclosures use the private channel described
in [SECURITY.md](https://github.com/nomed/yukh-coordination/blob/main/SECURITY.md).
