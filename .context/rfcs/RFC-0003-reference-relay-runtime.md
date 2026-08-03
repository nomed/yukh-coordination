# RFC-0003: Reference relay runtime

- Status: Accepted
- Governing issue: #5
- Owner: Nomed
- Date: 2026-08-03
- Scope: reference-relay implementation boundary

## Decision

The reference relay is implemented in Go. Its public edge uses HTTP for
commands and bounded reads, and Server-Sent Events (SSE) for ordered live
subscriptions. The public contract does not expose the persistence or messaging
technology used by an adapter.

SQLite is the first durable, single-node reference adapter. NATS JetStream is
the first distributed relay adapter. Matrix is a later human bridge and is not
part of the relay's persistence boundary.

This RFC authorizes implementation behind the protocol and security boundaries
already accepted in [RFC-0001](RFC-0001-protocol-v0.1.md) and
[RFC-0002](RFC-0002-mvp-security-boundary.md). It does not authorize deployment or
production operation.

## Why this shape

The relay has two distinct jobs: provide a stable coordination contract and
commit an authoritative transcript. HTTP and SSE keep the client contract
portable. Adapter ports keep SQLite and JetStream replaceable without allowing
either product to become the protocol.

IRC remains an architectural reference for rooms, presence and social
coordination. It is not the relay transport or database. Matrix will test the
human-room bridge when the relay contract is qualified.

## Runtime boundaries

The runtime is split into four layers:

1. the HTTP/SSE edge authenticates, bounds and translates requests;
2. the application core applies authorization and protocol transitions;
3. the append port commits accepted records and serves ordered replay;
4. adapters implement that port for memory, SQLite or JetStream.

Only the append port may allocate a server sequence. A successful append is one
atomic operation over canonical event bytes, identity and ACL bindings,
transcript epoch, sequence, idempotency state, event digest, receipt identity
and unsigned receipt preimage. Receipt signing and durable acknowledgement
remain governed by RFC-0002.

## Append-port contract

The first code increment defines the smallest persistence seam needed to prove
the contract:

- channels have an immutable tenant, internal ID, URI and transcript epoch;
- exact retries return the original accepted record without allocating a new
  sequence;
- reuse of an event ID with different canonical bytes is a collision;
- sequences are gap-free and strictly increasing within a transcript epoch;
- record preparation receives the allocated sequence and digest inside the
  append transaction;
- preparation failure commits nothing;
- reads return defensive copies in server-sequence order.

The record-preparation callback must be deterministic, side-effect free and
bounded. An adapter may invoke it again while retrying an optimistic
transaction. Network or signing operations are forbidden in that callback.

## Delivery order

1. qualify the port with an in-memory reference adapter;
2. implement and crash-test the SQLite adapter;
3. expose the qualified application service over HTTP and SSE;
4. implement the JetStream adapter against the same suite;
5. build the Matrix bridge as a client of the public contract.

The in-memory adapter is executable design evidence, not a production storage
option. SQLite, JetStream and Matrix each require their own focused change and
evidence. Provider-specific configuration stays outside the neutral core.

## Deferred decisions

Endpoint paths, authentication provider, deployment topology, JetStream stream
layout, Matrix room mapping and operational defaults are deliberately not
frozen here. They require evidence from their respective vertical slices.
