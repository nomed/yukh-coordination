# Current context

- Updated: 2026-08-05
- Governing issue: #167
- Last delivery pull request: #181
- Active Coordination increments: renewed RFC-0022 Step 5 is paused at #182
  after the restricted namespace foundation and immutable target pull exposed
  the non-root runtime-directory ownership gap; #6 composes the client process
  after #7 closed its two-process qualification
- Runtime decisions: RFC-0003 through RFC-0024 Accepted
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
  its private TLS listener and primitives pipeline composition in #100, and
  its mandatory fail-closed audit gate in #103, and its descriptor-delivered
  capability-key custody in #106, and its exact loopback JetStream/epoch
  composition in #109 at immutable implementation candidate `1af3ddb`; its
  immutable record and redacted, execution-forbidden deployment plan were
  published in #112; the closed, reproducibly qualified staging executable
  assembly was delivered in #121; task-first component documentation was
  published in #123; the accountable three-bucket bootstrap executable was
  delivered in #127; the canonical documentation header was aligned in #128;
  the superseding immutable candidate and execution-forbidden deployment plan
  were reconciled in #130; the bounded MCP handoff was recorded in #132;
  RFC-0023 fixed the mandatory transcript lifecycle and retention boundary in
  #134; its schema and capability-segregated port foundation was delivered in
  #140 and its non-destructive SQLite preparation transaction in #151; verified
  synthetic primary payload removal was delivered in #155; the RFC-0022 packet
  deferred-state gates were corrected in #161 and its immutable registry
  reference was bound in #162; the
  RFC-0022 operator packet was prepared in #138, consolidated in
  #146 and its first reproducible artifact digests recorded in #139 without
  authorizing provisioning or live traffic; RFC-0024 fixed the offline trust
  ceremony in #148 and its execution-forbidden tooling was delivered in #150
- Accepted design: RFC-0014 client credential custody and proof signing in #56,
  RFC-0018 Linux Secret Service custody composition in #70, RFC-0019 bounded
  capability accounting and terminal inspection in #76, and RFC-0020 Google
  Cloud workload custody in #79; RFC-0021 contention-response clarification in
  #83; RFC-0022 private staging primitives service profile in #92,
  RFC-0023 transcript lifecycle and retention in #134, and RFC-0024 private
  staging offline trust ceremony in #148; RFC-0025 explicit workstation
  bootstrap composition in #6; RFC-0026 explicit runtime custody profiles in
  #6; RFC-0027 isolated macOS Keychain reference in #6; RFC-0028 macOS legacy
  Keychain query compatibility in #6
- Next action: review and merge #182, reproduce/rebind its superseding OCI and
  reassess the server-leaf window before resuming Step 5. Separately
  implement and qualify the RFC-0025 Linux and RFC-0026 macOS workstation
  custody profiles;
  connect the client executable to the accepted bootstrap exchange, concrete
  custody and receipt verification adapters. Real backup providers, lifecycle workers,
  target pull, Kubernetes credentials and objects, Step 5, operational
  completion, worker, physical media sanitization, traffic, Matrix, MCP live
  use and production use remain separately gated

This file is a navigation aid, not an authority record. GitHub issues and the
Yukh Project own accepted delivery state.
