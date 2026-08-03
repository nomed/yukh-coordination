# RFC-0013: Client-neutral coordination CLI

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #6
- Governing architecture: RFC-0001, RFC-0002, RFC-0004, RFC-0008 and RFC-0009

## Decision requested

Freeze a provider-neutral command-line client through which isolated human and
agent sessions can discover active work, publish protocol signals and perform
explicit handoffs without provider-specific chat memory or user-mediated relay.

Acceptance authorizes a separately reviewed client library, CLI and synthetic
end-to-end qualification. It does not authorize a server binary, deployment,
external identity provider, credential minting or autonomous takeover.

## Product boundary

The CLI is a protocol client, not the coordinator. The durable relay transcript
remains authoritative. Git branches, worktrees, issue assignees, process lists,
chat history and CLI cache are observations only and never establish ownership.

The first required workflow is:

~~~text
session join -> work inspect -> claim -> progress -> review request -> verdict
             -> handoff offer -> handoff accept -> successor claim -> release
~~~

Claims remain visible assertions. They are not locks, leases, winner election or
project authority. Concurrent claims must be shown as conflicts, never hidden or
resolved by the CLI.

## Command surface

The executable is `yukh-coordination`. Version 1 exposes only:

~~~text
session bootstrap | join | leave
work inspect | claim | progress | release
question ask | answer
review request | verdict
handoff offer | accept
events replay | watch
version
~~~

Every mutating command accepts all protocol-significant values explicitly or in
one closed JSON input document. There are no interactive prompts, implicit git
remote discovery, current-branch ownership inference, environment-selected
tenant/channel, shell hooks or provider-specific subcommands.

`work inspect` is the mandatory discovery primitive before an agent starts or
takes over work. Its closed result includes transcript high-water, work state,
active claim identities, claim event IDs, claimant participant instance IDs,
latest progress summaries, current handoff offers and diagnostics. It never
returns credentials, private prompts or provider metadata.

## Configuration and session custody

Network configuration contains an exact HTTPS relay base URI and exact channel
URI. Configuration precedence is explicit flags, then one named configuration
file; ambient provider variables are ignored. Redirects, alternate endpoints,
proxy-derived identity and TLS downgrade are rejected.

`session bootstrap` uses RFC-0009 sender-constrained DPoP. External access tokens
enter only through a caller-owned file descriptor. The client generates an
ES256 DPoP key locally and never exports the private key.

Relay session token, participant identity, expiry and DPoP key are stored as one
versioned credential set using an operating-system credential-store port. A
plaintext repository file, working-directory file, command argument, environment
variable, Action output or shell history is forbidden. The reference Linux
adapter may use an explicitly selected secret service; tests use only an
in-memory fake. There is no silent plaintext fallback.

Every request creates a fresh bounded DPoP proof over the exact method and public
target. Session credentials are loaded only for the request and redacted from
errors, formatting, tracing and JSON output.

## Event construction and local state

The CLI creates UUIDv7 event, correlation, claim and handoff identifiers and
constructs only RFC-0001/schema-valid envelopes. Client time is advisory. The
authenticated participant identity always comes from the relay session and
cannot be overridden by a flag or input document.

Commands that extend a lifecycle require exact parent event IDs and generations.
The CLI may obtain them from an explicit `work inspect` result but must show and
submit the exact values. It performs no read-modify-write retry after a conflict.

A local cache may contain only public replay pages, signed receipts, cursors and
derived projections. Cache loss changes performance only. Cache content is
untrusted on load and cannot authorize a mutation, suppress a conflict or replace
a relay read. No active-claim timeout is inferred: disconnect, missing heartbeat,
session expiry and process death never release ownership.

## Output and exit contract

Default output is one closed JSON object on stdout. Human rendering is opt-in and
uses the same parsed result. Logs go to stderr and contain stable codes only.
Successful mutating output includes event ID, relay sequence, exact receipt
digest and idempotent-retry classification. Read output includes exact
high-water/completeness metadata.

Exit codes are stable:

- `0`: requested operation completed;
- `2`: local input or configuration invalid;
- `3`: authentication or session unavailable;
- `4`: access denied;
- `5`: protocol conflict or invalid transition;
- `6`: incomplete transcript or stale cursor requiring explicit inspection;
- `7`: temporary transport or relay unavailability;
- `8`: local credential-store failure;
- `9`: internal invariant failure.

Provider bodies, tokens, proofs, keys, endpoints containing user information and
unbounded error text never enter output.

## Replay and watch

`events replay` uses bounded RFC-0004 pages and verifies contiguous sequence and
signed receipts before advancing its cursor. `events watch` performs bounded
replay followed by SSE and reconnects only from the last verified sequence.
Reconnect uses bounded exponential delay with caller-configured deadline; it
does not claim liveness or mutate presence automatically.

`watch` emits each verified event once per process output stream. Duplicate SSE
delivery is suppressed only after exact receipt equality. Changed bytes,
sequence gaps, unsigned boundaries or invalid receipts terminate fail closed.

## Multi-provider integration

Codex, ChatGPT, Claude, Gemini and future clients use the same executable and
JSON contract. Provider integrations may wrap commands but may not reinterpret
claim state, store credentials in chat memory, hide conflicts or invent implicit
handoff. The repository golden paths may teach invocation; they do not fork the
protocol.

Until the relay process profile is executable, implementation qualification uses
an in-process deny-by-default HTTP/SSE test server built from the real handler.
This proves client behavior without adding an insecure development server or
weakening RFC-0008.

## Qualification

Acceptance requires:

- help and JSON-schema fixtures for every command;
- deterministic command-to-envelope tests for every signal family;
- credential redaction and no-plaintext-fallback tests;
- DPoP exact method/URI, replay and key-substitution negatives;
- concurrent claim visibility and no implicit winner selection;
- exact-parent conflict, late handoff and competing acceptance negatives;
- replay pagination, duplicate delivery, sequence gap and reconnect tests;
- stable output and exit codes under sanitized provider failures;
- two isolated CLI processes completing the issue #7 scenario against the real
  handler with no user-mediated message copying.

## Compatibility and rollout

The CLI consumes the accepted HTTP/SSE and protocol v0.1 contracts and changes
neither. Output schema and command spelling are versioned independently. The
first implementation remains unreleased until conformance and an independent
review pass. Rollback removes the client only; it changes no relay state.

## Alternatives rejected

- GitHub issues, branches and worktrees alone are durable project evidence but
  do not provide live cross-provider claims, questions or handoffs.
- Provider chat memory and proprietary subagent APIs cannot coordinate isolated
  sessions or other vendors.
- A local lock file cannot cross hosts and would falsely turn advisory claims
  into authority.
- Shipping an allow-all local relay would violate RFC-0008 and hide the actual
  deployment/security work.
