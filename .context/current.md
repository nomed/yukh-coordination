# Current context

- Updated: 2026-08-13
- Governing issues: #6, #167, #184 and #195
- Last delivery pull request: #204
- Active Coordination increment: #6 connects the client CLI to the accepted
  bootstrap exchange and then to concrete custody and receipt verification
- Runtime decisions: RFC-0003 through RFC-0025 Accepted
- Accepted decision: RFC-0025 defines the execution-forbidden Coordination
  profile for accepted `nomed.github.io` RFC-0005 on `main` at
  `12d9215f10c4b7fb1762a5025367e3e81543800f`. The project owner explicitly
  accepted it in #195 on 2026-08-09 by stating "Accetto tutti e tre".
  Acceptance authorizes only separately reviewed execution-forbidden
  implementation and hermetic synthetic qualification; it authorizes no
  runtime code, infrastructure, OCI publication, credentials outside
  test-owned ephemeral processes, live traffic, provider execution, mutation,
  preview publication, production use or readiness claims.
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
  #140, its non-destructive SQLite preparation transaction in #151, verified
  synthetic primary payload removal in #155, and its synthetic backup evidence
  and completion persistence in #168; the RFC-0022 packet
  deferred-state gates were corrected in #161 and its immutable registry
  reference was bound in #162; the
  RFC-0022 operator packet was prepared in #138, consolidated in
  #146 and its first reproducible artifact digests recorded in #139 without
  authorizing provisioning or live traffic; RFC-0024 fixed the offline trust
  ceremony in #148 and its execution-forbidden tooling was delivered in #150
  and completed in #166; the coordination event publication, conversation
  events and CLI signal boundaries were delivered in #170, #172, #173 and #175;
  the four-agent, two-process qualification closed in #176 and #178; the client
  process boundary and bootstrap saga were delivered in #180 and #181; the
  PodIP-aware launcher and immutable OCI evidence were corrected in #171 and
  #179; the non-root runtime-directory boundary was closed in #183; the
  JetStream state and secret boundaries were documented in #189; issue #184
  preparation was completed in #192 from executable/OCI reproduction source
  `92678da9`, with preparation commit `97fe3086`; #193 bound the corrected,
  distinct delivery identity `806f9e1c`
- Accepted design: RFC-0014 client credential custody and proof signing in #56,
  RFC-0018 Linux Secret Service custody composition in #70, RFC-0019 bounded
  capability accounting and terminal inspection in #76, and RFC-0020 Google
  Cloud workload custody in #79; RFC-0021 contention-response clarification in
  #83; RFC-0022 private staging primitives service profile in #92,
  RFC-0023 transcript lifecycle and retention in #134, RFC-0024 private staging
  offline trust ceremony in #148, and RFC-0025 first usable preview Coordination
  profile in #195
- Next action: issue #184 preparation is complete. Private OCI publication and
  provider comparison, server-leaf rotation, and RFC-0022 Steps 5, 6 and 7
  remain gated and require separate explicit authorization. Separately, #6
  now has concrete descriptor-backed local root-key custody, pinned receipt
  verification, a closed executable composition and verified SSE watch. Client
  RC packaging is delivered; macOS artifacts and local JetStream owner
  qualification are under review.
  RFC-0023 lifecycle-worker composition remains design-only in #177.
  Real backup providers, lifecycle workers, target pull, Kubernetes credentials
  and objects, Step 5, operational completion, physical-media sanitization,
  traffic, Matrix, MCP live use and production use remain separately gated
- First usable preview gate: RFC-0025 is accepted in #195. Acceptance
  authorizes only separately reviewed execution-forbidden implementation and
  hermetic synthetic qualification; it authorizes no runtime code,
  infrastructure, OCI publication, credentials outside test-owned ephemeral
  processes, live traffic, provider execution, mutation, preview publication,
  production use or readiness claims. A separate implementation issue remains
  required before any implementation work.

This file is a navigation aid, not an authority record. GitHub issues and the
Yukh Project own accepted delivery state.
