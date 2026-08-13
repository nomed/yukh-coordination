# Session 2026-08-13 — CLI custody and receipt adapters

Issue #6 continues after bootstrap HTTPS adapter PR #201.

This increment adds two execution-neutral adapters:

- a profile-bound local-custody root key source that consumes one inherited
  descriptor and retains no plaintext file or environment fallback;
- an Ed25519 receipt verifier that validates the closed receipt schema,
  canonical bytes, explicit trusted key ID, domain-separated signature input,
  and signature before publish or replay can accept a record.

The executable remains intentionally uncomposed. The next increment must parse
one closed configuration, construct local custody, bootstrap and the client,
then qualify the full flow against the real handler. No live traffic,
provisioning or JetStream deployment is authorized by this work.
