# Current context

- Updated: 2026-08-03
- Governing issue: #6
- Last delivery pull request: #100
- Active increment: none; #98 and #100 are delivered and their follow-on work
  remains separately gated
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
  delivered in #91; the closed RFC-0020 Storage/KMS profile composition and
  synthetic end-to-end qualification were delivered in #98; RFC-0022 selects
  the private staging primitives service profile in #92, its configuration,
  DPoP authentication and durable replay foundation was delivered in #96, and
  its private TLS listener and primitives pipeline composition in #100
- Accepted design: RFC-0014 client credential custody and proof signing in #56,
  RFC-0018 Linux Secret Service custody composition in #70, RFC-0019 bounded
  capability accounting and terminal inspection in #76, and RFC-0020 Google
  Cloud workload custody in #79; RFC-0021 contention-response clarification in
  #83; RFC-0022 private staging primitives service profile in #92
- Next actions ready for separate ownership: the bounded RFC-0022 mandatory
  audit, capability-key custody and exact JetStream/epoch composition
  increments; any RFC-0020 WIF and isolated-cloud qualification must be a new,
  separately owned increment. Live infrastructure, credentials, external-token
  selection, bootstrap, protected mutations and production use remain
  separately gated

This file is a navigation aid, not an authority record. GitHub issues and the
Yukh Project own accepted delivery state.
