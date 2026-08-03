# RFC-0004: HTTP/SSE binding v1

- Status: Proposed
- Author: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #5
- Governing architecture: RFC-0001, RFC-0002 and RFC-0003

## Decision requested

Accept the first public transport binding for the Yukh Coordination relay:
versioned HTTP commands and bounded replay plus an SSE live stream, without
exposing SQLite, JetStream, Matrix or an authentication provider.

This RFC does not authorize deployment, public admission or production use.
Implementation may proceed as an internal candidate, but the routes and wire
behavior below are not a compatibility commitment until this RFC is Accepted.

## Goals

- one provider-neutral contract usable by agents, CLIs and bridges;
- authenticate and authorize before resource existence is disclosed;
- preserve exact canonical event and signed-receipt bytes;
- make replay, reconnect, idempotency and incomplete boundaries explicit;
- bound bodies, pages, stream lifetime and buffering;
- keep protocol versioning independent from transport versioning.

## Non-goals

- browser-native `EventSource` convenience;
- WebSocket, bidirectional RPC, federation or offline ingestion;
- channel administration, ACL mutation, retention or deletion endpoints;
- authentication-provider discovery or token issuance;
- public deployment topology or service-level objectives.

## Standards profile

The binding follows HTTP semantics from RFC 9110, Problem Details from RFC
9457, Bearer token transport from RFC 6750 and the WHATWG server-sent event
wire format. Bearer transport requires TLS. Tokens never appear in paths,
queries, events, receipts or logs.

SSE is a wire-format choice, not a dependency on the browser `EventSource`
API. Clients that require an `Authorization` header may use any streaming HTTP
client that implements `text/event-stream` parsing and `Last-Event-ID`.

## Version and media types

The binding prefix is `/coordination/v1`. Binding version `v1` can carry Yukh
protocol `specversion` 0.1; the two versions do not imply each other.

| Representation | Media type |
| --- | --- |
| canonical client event | `application/yukh-event+json;version=0.1` |
| signed receipt | `application/yukh-receipt+json;version=0.1` |
| bounded transcript page | `application/yukh-transcript+json;version=0.1` |
| live record stream | `text/event-stream` |
| error | `application/problem+json` |

Request content encoding is `identity` only. Compressed request bodies are
rejected. Successful and error responses use `Cache-Control: no-store`.

## Resource identity

The authenticated identity supplies `tenant_id`; clients cannot select it in a
path, query, header or body. Routes contain the immutable internal `channel_id`
and one `transcript_epoch`:

```text
/coordination/v1/channels/{channel_id}/transcripts/{transcript_epoch}
```

Path segments use their exact decoded value after strict percent-decoding.
Empty values, encoded separators, dot segments, invalid UTF-8, repeated
decoding and non-canonical escaping are rejected before resource lookup.

## Authentication and admission order

The edge applies one order:

1. method, header-count, request-target and framing bounds;
2. Bearer authentication over TLS;
3. derive tenant, principal, participant instance and session epoch;
4. authorize `(tenant, channel, principal, action)` without disclosing
   existence;
5. look up immutable channel and transcript identity;
6. validate media type, canonical protocol bytes and transition;
7. execute the application service.

Missing or invalid authentication returns `401` with a bounded
`WWW-Authenticate: Bearer` challenge. After authentication, missing and denied
tenant/channel/transcript state return the same `404` Problem Details shape and
observable posture. Only an admitted caller receives validation detail.

Forwarded identity headers, cookies, query tokens, event participant labels and
display names never establish authentication or authorization.

## Append

```http
POST /coordination/v1/channels/{channel_id}/transcripts/{transcript_epoch}/events
Content-Type: application/yukh-event+json;version=0.1
Authorization: Bearer ...
```

The body is exactly one canonical JCS event, with a maximum of 65,536 UTF-8
bytes and no trailing content. The event channel URI must equal the immutable
URI registered for the routed identity. Event ID comes only from the validated
event body.

The edge calls the signed-append service. It returns:

- `201 Created` plus the canonical signed receipt for a new append;
- `200 OK` plus the original canonical signed receipt for an exact retry;
- `409 Conflict` for the same event ID with changed canonical bytes;
- `422 Unprocessable Content` for an admitted invalid event or transition;
- `429 Too Many Requests` for an admitted quota failure;
- `503 Service Unavailable` with bounded `Retry-After` when commit outcome is
  indeterminate or the original durable signature remains pending.

No `2xx` response is produced before the signature is durably attached. A
`503` cannot authorize a replacement event; the client retries the exact event
ID and canonical bytes.

## Bounded replay

```http
GET /coordination/v1/channels/{channel_id}/transcripts/{transcript_epoch}/records?after={sequence}&limit={count}
Accept: application/yukh-transcript+json;version=0.1
Authorization: Bearer ...
```

`after` is an unsigned decimal server sequence and is exclusive. It defaults
to `0`. Leading signs, whitespace, alternate bases and leading zeroes other than
`0` are invalid. `limit` defaults to `100` and is bounded to `1..1000`.

The response contains the exact channel identity, transcript epoch, requested
cursor, returned high-water sequence, `complete` or `incomplete`, and ordered
records containing exact canonical event and signed-receipt representations.

Replay never skips an unsigned or permanently un-signable receipt. It stops
before the first such sequence, reports `incomplete` and identifies that
sequence as the boundary without exposing mutable signer diagnostics. Records
after that boundary are not returned as a continuous transcript.

## Live stream

```http
GET /coordination/v1/channels/{channel_id}/transcripts/{transcript_epoch}/stream
Accept: text/event-stream
Authorization: Bearer ...
Last-Event-ID: {sequence}
```

The optional `Last-Event-ID` is the exclusive server-sequence cursor and uses
the same canonical decimal rules as `after`. A query cursor is deliberately
not supported for the stream, preventing ambiguous precedence and accidental
token/cursor copying into URLs.

After admission, the response uses:

```http
Content-Type: text/event-stream
Cache-Control: no-store, no-transform
```

Each signed accepted record is one SSE event:

```text
id: 42
event: record
data: {one-line canonical record JSON}

```

The edge first replays from the cursor and then continues live without a race
gap. `id` is the decimal server sequence. Event data contains no literal CR or
LF outside JSON escaping. The stream sends a comment heartbeat at most every
15 seconds of inactivity and a `retry: 3000` advisory once after connection.

If the next sequence is unsigned, the edge emits one `boundary-incomplete`
event without an `id`, then closes. Because no new ID was committed by the
client, reconnect requests the same boundary. The stream never emits a later
sequence across that gap.

Each connection has bounded pending bytes and a configured maximum lifetime no
greater than 15 minutes. Slow consumers are disconnected without advancing
their cursor. Normal EOF permits reconnect. An authorized lifecycle transition
to deleted or access revocation terminates delivery immediately; no event body
is written after the revocation decision.

## Problem details

Errors use RFC 9457 and a closed v1 `type` vocabulary under
`urn:yukh:coordination:problem:*`. The body contains `type`, `title`, `status`,
`code` and a correlation-safe request ID. It excludes credentials, event
bodies, policy internals, SQL/broker errors and resource existence details.

The authenticated missing-or-denied response uses one type, code, title and
status. Internal security audit records the detailed cause separately.

## Cursors and delivery semantics

Server sequence is the v1 cursor. It is scoped by authenticated tenant,
immutable channel ID and transcript epoch; moving a cursor to any other scope
is invalid. SSE delivery is at least once across reconnect. Event ID and signed
receipt identity make duplicate delivery safe. Client arrival time has no
semantic role.

The server does not promise that an SSE connection itself is durable. The
SQLite or JetStream adapter owns transcript durability; SSE is only an ordered
delivery view over signed records.

## Implementation and qualification plan

1. implement strict route, header, cursor and media-type parsing;
2. implement authenticator and authorizer ports with deny-by-default fakes;
3. expose append only through the signed-append service;
4. qualify bounded replay including unsigned boundaries;
5. qualify race-free replay-to-live handoff and slow-consumer disconnect;
6. publish an OpenAPI document for request/response operations;
7. publish an AsyncAPI document for the SSE channel after executable behavior
   and schema round trips agree.

## Required evidence before acceptance

- authentication precedes resource lookup and validation detail;
- missing and denied resources are externally indistinguishable;
- client-selected tenant and forwarded identity are ignored/rejected;
- oversized, compressed, malformed, duplicate-key and non-canonical events
  never append;
- exact retry returns the original signed receipt;
- signer/commit uncertainty never returns `2xx`;
- replay bounds and cursor scope are enforced;
- reconnect produces no gap or semantic duplicate;
- unsigned boundary prevents later delivery;
- access revocation and slow-consumer behavior are deterministic;
- logs contain no token, event body or policy internals.

## Alternatives considered

### WebSocket first

Rejected for v1. Bidirectional session state adds flow-control, reconnect and
authorization complexity without improving the append/replay contract.

### Broker-native clients

Rejected. NATS or Matrix bindings would leak adapter topology into the public
protocol and prevent independent replacement.

### Long polling only

Retained as possible future fallback, but not selected as the primary live
view. SSE supplies an established ordered reconnect format while preserving
ordinary HTTP admission.

### Tenant in the path

Rejected because tenant identity is relay-derived. A client-selected tenant
would weaken the isolation boundary and create an enumeration surface.

## References

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 9457 — Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [WHATWG HTML — Server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
