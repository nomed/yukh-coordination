<p align="center">
  <a href="https://nomed.github.io/system/coordination/"><img src=".github/assets/repository-mark.svg" width="96" alt="Yukh Coordination"></a>
</p>

<h1 align="center">Yukh Coordination</h1>

<p align="center"><a href="https://nomed.github.io/system/coordination/">Role in the Yukh system</a></p>

> Two isolated sessions can discover each other's ownership and progress, ask questions, exchange verifiable evidence, and complete a handoff without using the user as their coordination channel.

Yukh Coordination is an open, client-neutral coordination protocol for people and agents working across isolated sessions.

[Documentation](https://nomed.github.io/yukh-coordination/) · [First replay](https://nomed.github.io/yukh-coordination/tutorials/first-replay/)

It is not a supervisor, an agent runtime, or a source of authority. It provides shared rooms, durable signals, explicit ownership, evidence references, and observable handoffs. The project remains responsible for deciding who may act and what constitutes acceptance.

## Status

**Foundation / reference implementation. Not production-ready.**

The first milestone proves one bounded flow:

```text
JOIN → CLAIM → PROGRESS → QUESTION → ANSWER
     → REVIEW_REQUEST → VERDICT → HANDOFF → RELEASE
```

## Product boundary

- Yukh MCP governs capabilities.
- Yukh Projects reconciles roadmap and delivery state.
- Yukh Coordination makes cross-session work legible.

These projects may integrate, but none owns the others.

## MVP proof

The MVP succeeds when two real isolated sessions, with at least four agents in total, can:

1. join the same channel;
2. discover active participants and claims;
3. publish progress without overwriting history;
4. ask and answer a correlated question;
5. attach immutable evidence references;
6. request and receive an independent verdict;
7. transfer ownership through an explicit handoff;
8. release the claim with a replayable transcript.

See [CHARTER.md](CHARTER.md), [PROTOCOL.md](PROTOCOL.md), the
[context map](.context/README.md), and
[ADR-0001](.context/decisions/ADR-0001-protocol-not-control-plane.md).

## Reference relay

The reference relay is being built in Go behind a transport-neutral append
port. HTTP/SSE is the public edge, SQLite is the first durable single-node
adapter, and NATS JetStream is the first distributed adapter. See
[RFC-0003](.context/rfcs/RFC-0003-reference-relay-runtime.md) for the boundaries and
delivery order.

The qualified layers now have an internal typed composition and lifecycle
boundary governed by
[RFC-0007](.context/rfcs/RFC-0007-relay-composition-lifecycle.md). The relay and
private primitives process are unreleased implementation candidates. They
require an explicitly qualified deployment profile and are not a public
installation path.

Run the current relay contract tests with:

```sh
go test ./...
```

## License

Apache License 2.0.
