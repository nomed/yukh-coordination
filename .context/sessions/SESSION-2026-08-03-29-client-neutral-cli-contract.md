# Session: Client-neutral coordination CLI contract

- Date: 2026-08-03
- Governing issue: #6
- Pull request: pending
- Status: proposed contract

## Objective

Turn the observed cross-session ownership failure around `yukh-projects` PR #74
into the first usable, provider-neutral Coordination client boundary.

## Work completed

Drafted RFC-0013. It separates the client from the still-gated process binary,
requires `work inspect` before takeover, freezes explicit commands and JSON/exit
contracts, preserves claims as non-authoritative assertions, and defines secure
DPoP session custody without plaintext fallback.

## Evidence and validation

The proposal was checked against RFC-0001 event semantics, RFC-0004 HTTP/SSE,
RFC-0008 process gates and RFC-0009 DPoP sessions. No executable, dependency,
credential adapter, server profile or deployment was added.

## Context impact

RFC-0013 remains Proposed. Owner acceptance is required before implementation.

## Risks and unresolved work

The real single-node process remains gated by RFC-0008. Initial CLI qualification
must therefore use the real handler in process and must not introduce an allow-all
development relay.
