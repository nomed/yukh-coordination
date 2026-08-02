# Project charter

## Purpose

Make coordination between isolated human and agent sessions observable, durable, interoperable, and reviewable.

## In scope

- channels and participant presence;
- bounded work claims and explicit release;
- progress, questions, answers, review requests, and verdicts;
- content-addressed or immutable evidence references;
- explicit handoffs;
- replayable transcripts;
- protocol conformance fixtures;
- a minimal reference relay and CLI after the protocol boundary is accepted.

## Out of scope

- granting execution authority or credentials;
- selecting which agent should perform work;
- silently reassigning abandoned work;
- replacing project governance or roadmap systems;
- transporting secrets or unrestricted tool output;
- becoming a proprietary orchestration platform;
- assuming GitHub, Codex, MCP, or any one model provider.

## Invariants

1. The channel informs; it does not authorize.
2. Ownership is explicit, scoped, and observable.
3. Handoff and release are never inferred from silence or elapsed time.
4. Durable events are append-only.
5. Evidence is referenced, not trusted merely because it was announced.
6. People and agents use the same participant model.
7. Protocol conformance is independent of the reference implementation.
8. Maturity is stated truthfully; visual polish is not release evidence.

## Governance posture

The project is maintainer-led during foundation. Material decisions about the public protocol, persistence boundary, identity, security, compatibility, or topology require an ADR or RFC and public review.
