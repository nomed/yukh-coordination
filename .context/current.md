# Current context

- Updated: 2026-08-03
- Governing issue: #6
- Last delivery pull request: #94
- Active increment: #95 implements the RFC-0022 closed configuration,
  signed-registration, DPoP and durable replay foundation; listener and service
  composition remain a later increment
- Runtime decisions: RFC-0003 through RFC-0022 Accepted
- Completed delivery: RFC-0011 in #47, RFC-0012 in #46, the RFC-0013
  read-only client foundation in #52, its DPoP credential foundation in #53,
  the RFC-0014 neutral client-authentication refactor in #62, the RFC-0017
  two-phase authorization implementation in #69, the environment-neutral
  RFC-0018 encrypted custody foundation in #73, and the accepted RFC-0019
  bounded capability-accounting design in #76; the RFC-0020 Google Cloud
  workload custody profile was accepted in #79; the RFC-0015/16/17/19
  client-neutral primitives boundary and qualification were delivered in #71;
  the RFC-0020 envelope and provider-contract foundation was delivered in #82;
  RFC-0021 clarifies lease-acquisition contention as `409 conflict` in #83;
  the RFC-0020 Cloud Storage `CredentialStore` adapter was delivered in #87;
  the RFC-0020 Cloud KMS raw-encryption and `ProofSignerStore` adapters were
  delivered in #91; RFC-0022 selects the private staging primitives service
  profile in #92
- Accepted design: RFC-0014 client credential custody and proof signing in #56,
  RFC-0018 Linux Secret Service custody composition in #70, RFC-0019 bounded
  capability accounting and terminal inspection in #76, and RFC-0020 Google
  Cloud workload custody in #79; RFC-0021 contention-response clarification in
  #83; RFC-0022 private staging primitives service profile in #92
- Next actions ready for separate ownership: after review of #95, the bounded
  RFC-0022 listener and primitives pipeline composition increment; the bounded RFC-0020 explicit
  profile-composition and synthetic end-to-end qualification increment over
  the delivered Storage and KMS adapters; and the separately reviewed
  RFC-0022 hermetic private-staging implementation. WIF, live infrastructure,
  credentials, external-token selection, bootstrap, protected mutations and
  production use remain separately gated

This file is a navigation aid, not an authority record. GitHub issues and the
Yukh Project own accepted delivery state.
