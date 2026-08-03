# RFC-0021: Lease-acquisition contention response clarification

- Status: Accepted
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Accepted: 2026-08-03
- Decider: project owner
- Governing issue: #83
- Governing architecture: RFC-0012, RFC-0015, RFC-0017 and RFC-0019

The project owner explicitly accepted this clarification in issue #83 on
2026-08-03. It supersedes only the inconsistent lease-acquisition contention
sentence in RFC-0015. All other accepted RFC-0015 semantics remain unchanged.

## Decision

A contended
`POST /coordination-primitives/v1/leases:acquire` request returns bounded Problem
Details with HTTP status `409` and code `conflict`.

`contended` is not a successful `2xx` outcome in Coordination primitives v1.
The only successful lease-acquisition outcome is `acquired`, returned in the
closed lease response with `specversion`, `lease_capability`, `fencing_token`
and `expires_at`.

The RFC-0015 statement “Acquire outcomes are `acquired` or `contended`” is
superseded by this record. Its later requirement that contention is a
deterministic non-success with no implicit retry remains valid.

## Motivation

RFC-0015 described `contended` as an acquire outcome, but the accepted and
merged executable contract consistently uses `409 conflict`:

- `schema/coordination-primitives-1.schema.json` excludes `contended` and
  admits `conflict` Problem Details;
- `js/lib/primitives-client.mjs` accepts only `acquired` as acquisition success
  and validates `409 conflict`;
- `internal/primitiveshttp/handler.go` maps the closed conflict error to bounded
  `409 conflict` Problem Details;
- `internal/primitiveshttp/bridge_test.go` proves a second contending holder
  receives exactly that response.

Keeping the executable contract avoids a breaking wire change and removes the
need for independent consumers to guess whether contention is transport
success or a typed problem.

## Normative response

The response status is `409`. Its canonical closed body is:

~~~json
{"code":"conflict","status":409,"title":"conflict","type":"urn:yukh:coordination-primitives:problem:conflict"}
~~~

The response uses the RFC-0015 primitives media type and `Cache-Control:
no-store`. It contains no scope, holder, tenant, principal, lease, capability,
fencing, expiry, provider or storage detail.

A consumer MUST treat the response as deterministic non-acquisition. It MUST
NOT infer ownership, expose a lease capability, call the protected operation,
or retry implicitly. Any later acquisition attempt is a new explicitly
authorized consumer decision under its own current preconditions and deadline.

## Trust boundaries and threat analysis

This record introduces no new trust boundary and changes no executable behavior.
It prevents two unsafe interpretations:

- treating contention as a successful transport result that might accidentally
  advance a protected-operation lifecycle;
- treating a typed deterministic conflict as an ambiguous provider outage that
  might trigger hidden retry.

Existing RFC-0015 authentication, two-phase authorization, non-enumerating
error, redaction, call-count, deadline, no-retry and capability controls remain
normative.

## Compatibility

This clarification is wire-compatible with the implementation merged by PR #71
at `03a64aa84a530273c452ba28d369b4b877dbfea4`. It requires no schema, client,
handler, storage, capability, route, media-type or conformance-fixture change.

Consumers that implemented the contradictory RFC prose rather than the public
schema and client must update to accept `409 conflict` and reject `2xx
contended`. No version 1 server is authorized to emit `2xx contended`.

## Rollout and rollback

Publication of this accepted record completes the clarification. Existing
executable tests remain the byte- and behavior-level evidence. Rollback is not
an executable operation; superseding this response would require a new accepted
RFC, explicit compatibility analysis and a new protocol version where needed.

## Authorization boundary

Acceptance authorizes this immutable clarification record and consumer
compatibility review only. It does not authorize deployment, a public listener,
credentials, protected consumer use, publication, live apply, changes in
`yukh-mcp`, or renewed work under closed issue #58.
