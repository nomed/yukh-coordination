# RFC-0009: Session bootstrap and request authentication contract

- Status: Proposed
- Authors: Nomed with implementation support
- Created: 2026-08-03
- Governing issue: #5
- Governing architecture: RFC-0002, RFC-0004, RFC-0005 and RFC-0008

## Decision requested

Freeze the public session-bootstrap exchange and the provider-neutral request
authentication material used by the single-node reference profile.

Acceptance authorizes implementation of this transport and port contract with
fakes and qualification tests. It does not authorize an RFC 9068 validator,
DPoP verifier, identity database, policy provider, public listener or process
binary. Those remain separate increments under RFC-0008.

This RFC is an additive revision to RFC-0004. Where their authentication
schemes differ, this RFC governs the `single-node-v1` profile.

## Boundary

The HTTP edge owns bounded framing, extraction of credentials and proofs, and
construction of the public request method and URI. It does not parse JWT
claims, verify JWS signatures, calculate JWK thumbprints, allocate epochs,
generate session tokens or persist replay state.

Two ports remain deliberately distinct:

1. `SessionBootstrapper` consumes external bootstrap authentication and
   returns one newly issued relay session;
2. `Authenticator` consumes relay-session authentication and returns an
   immutable admitted identity.

The external access token never passes through the ordinary resource
`Authenticator`. A relay session token never passes through the bootstrap
port. Neither credential reaches `Authorizer`, `Application`, `Store`, event
bytes or receipt bytes.

## Public bootstrap operation

The profile adds exactly one public route:

```http
POST /coordination/v1/sessions
Authorization: DPoP {external-access-token}
DPoP: {compact-JWS-proof}
Content-Length: 0
```

The request has no query, body, `Content-Type`, content encoding, cookies or
client-selected tenant. Chunked framing, a non-zero content length, any body
octet and multiple `Authorization` or `DPoP` fields are rejected before a
provider call. TLS remains mandatory.

The external JWT access token is sender-constrained: its `cnf.jkt` identifies
the same client key carried by the RFC 9449 proof. The proof binds `POST`, the
normalized public session URI and the access token through the standard `ath`
claim. The authorization scheme is therefore `DPoP`, not `Bearer`.

This tightens the bootstrap wording in RFC-0008. The session route is a
protected resource, not an OAuth token endpoint; accepting a Bearer token next
to an otherwise unrelated proof would not prevent a holder of a stolen token
from substituting a new proof key.

The provider must validate the complete RFC-0008 external-token and DPoP
profile and record the security audit entry before returning success. The edge
does not infer which stage failed.

## Successful response

A newly created session returns `201 Created` with:

```http
Content-Type: application/yukh-session+json;version=0.1
Cache-Control: no-store
Pragma: no-cache
```

The body is one JCS-canonical UTF-8 JSON object with exactly these members:

```json
{
  "expires_at": "2026-08-03T05:30:00.000Z",
  "participant_instance_id": "01989f0e-56b7-7e01-915e-a7748f7f6204",
  "session_epoch": 7,
  "session_token": "base64url-without-padding",
  "specversion": "0.1",
  "token_type": "DPoP"
}
```

The field contract is closed:

- `session_token` is the new 256-bit opaque token encoded as 43 base64url
  characters without padding;
- `participant_instance_id` is the canonical lowercase UUIDv7 allocated for
  this connection identity;
- `session_epoch` is a positive JSON safe integer monotonically allocated for
  the authenticated `(tenant_id, principal_id)`;
- `expires_at` is UTC RFC 3339 with exactly millisecond precision, later than
  issuance and no more than 15 minutes after it;
- `token_type` is exactly `DPoP` and `specversion` is exactly `0.1`.

The token appears only in this response. There is no `Location`, refresh token,
cookie, resume handle or session lookup route. Retrying bootstrap creates a new
participant instance and epoch; it is not an idempotent replay of a previous
secret response.

Before writing success, the edge validates the returned structural bounds and
canonicalizes the closed response itself. A malformed provider result becomes
a sanitized `503`; it is never partially serialized.

## Authentication on resource routes

Append, replay and stream requests change from the RFC-0004 Bearer profile to:

```http
Authorization: DPoP {relay-session-token}
DPoP: {compact-JWS-proof}
```

The proof is fresh and carries the standard `ath` claim for the relay session
token. The request-aware `Authenticator` verifies the session, proof, replay
window and revocation and returns the existing closed `Identity` value. The
authorization and application order after authentication does not change.

Bearer relay sessions are not accepted as a compatibility fallback. External
access tokens are not accepted on resource routes. Cookies, query
parameters, forwarded headers and event identity remain non-authoritative.

## Closed authentication material

The edge constructs one of two immutable values after route, framing and TLS
checks.

Bootstrap material contains only:

- external DPoP-bound access-token credential;
- compact DPoP proof;
- exact uppercase HTTP method;
- normalized public target URI.

Session material contains only:

- opaque relay session credential;
- compact DPoP proof;
- exact uppercase HTTP method;
- normalized public target URI.

The Go representation uses unexported fields, bounded constructors and
explicit accessors. It implements redacted `String` and `GoString` methods so
routine formatting cannot disclose either secret. Accessors are required only
at the provider boundary and callers must not retain returned strings.

There is no generic map, raw `http.Request`, header collection, context value
or provider-specific claim bag in either port. This prevents provider code
from trusting `Host`, forwarded identity, cookies or unrelated headers and
keeps HTTP ownership at the edge.

## Public target normalization

The handler configuration receives one prevalidated HTTPS public base URI from
the later strict process configuration. It has a scheme and authority, no user
information, query or fragment, and an optional canonical escaped path prefix.

For proof material the edge appends the routed canonical escaped path to that
base. It never uses request `Host`, `Forwarded`, `X-Forwarded-*` or TLS server
name. As required by RFC 9449 `htu` comparison, query and fragment components
are excluded. Method is the exact uppercase method admitted by the route.

Construction failure occurs before any authentication provider call.

## Bounds and parsing

The edge applies independent limits before provider invocation:

- one `Authorization` field, at most 8,192 bytes;
- one `DPoP` field, at most 16,384 bytes;
- compact proof has exactly three non-empty base64url-without-padding segments;
- no whitespace, comma folding or control character in either credential;
- existing 4,096-byte request-target and 64-header limits remain;
- bootstrap has no body; resource body rules remain unchanged.

These checks establish safe framing only. They do not decode or semantically
validate JWT/JWS content; that belongs to the later provider.

## Failure contract

Every authentication failure is bounded Problem Details and `Cache-Control:
no-store`. It contains no token, proof, claim, JWK, tenant, principal, key ID or
provider error text.

Bootstrap authentication failure returns `401 unauthenticated` with the
profile challenge:

```http
WWW-Authenticate: DPoP algs="ES256"
```

Resource authentication failure returns the same public Problem Details shape
and challenge. The response does not reveal
whether token, proof, key binding, time window or replay check failed.

Provider unavailability or inability to durably create/audit a session returns
`503 temporarily_unavailable` with bounded `Retry-After`. Invalid framing,
route or forbidden bootstrap body returns `400 invalid_request` before any
provider call.

## Port results and error classes

The bootstrap port returns either one complete `IssuedSession` or one closed
error class:

- unauthenticated;
- temporarily unavailable.

The resource authenticator returns either one complete `Identity` or the same
closed error classes. The edge maps all unknown provider errors to temporarily
unavailable and never exposes their text. A zero or malformed success value is
also temporarily unavailable.

Providers receive the request context for cancellation. Cancellation cannot
turn an unconfirmed session creation into `2xx`; the later identity provider
must define atomic creation and audit behavior.

## API construction

`httpapi.New` gains the bootstrap port and the normalized public base URI as
mandatory dependencies. There is no overload that silently installs a fake or
retains Bearer resource authentication.

The runtime composition gains the same bootstrap dependency. Existing tests
must supply explicit deny-by-default or deterministic fakes. This intentional
compile-time break prevents a caller from constructing the revised public edge
with the old bearer-only security posture.

## Required qualification

Implementation must prove:

- bootstrap is the only route accepting an external DPoP-bound access token;
- resource routes require both DPoP authorization and proof;
- framing, TLS and public-target construction precede every provider call;
- bootstrap rejects query, body, content type, compression and chunking;
- duplicate, oversized, whitespace-bearing and malformed compact credentials
  never reach a provider;
- Host and every forwarding header cannot change provider-visible method/URI;
- the external token never reaches resource authentication and the relay token
  never reaches bootstrap;
- malformed successful provider results never produce `2xx`;
- the success body is byte-deterministic JCS and contains no extra member;
- error challenges and Problem Details are exact and non-oracular;
- provider error strings and all credential bytes are absent from responses;
- redacted formatting of authentication material does not reveal secrets;
- existing append, replay, SSE ordering and revocation tests still pass under
  the revised DPoP edge;
- runtime construction fails when bootstrap or public-base dependencies are
  absent.

Tests use deterministic opaque strings and syntactically framed compact JWS
values. They do not fake cryptographic verification and then claim DPoP
qualification; that evidence belongs to the provider increment.

## Compatibility

The bootstrap route and session media type are additive. Changing resource
authorization from Bearer to DPoP is a deliberate pre-release break of an
unshipped binding. Event, receipt, page and SSE representations do not change.

No configuration schema, OpenAPI document or external SDK compatibility is
claimed in this increment. OpenAPI is updated only after executable handler
behavior and fixtures agree.

## Alternatives rejected

### One authenticator for both trust domains

Rejected because it would branch on credential type inside a security-critical
provider and blur external principal validation with relay session admission.

### Pass the raw HTTP request to providers

Rejected because it transfers trust in Host, forwarding headers, cookies and
framing from the edge to every provider implementation.

### Keep Bearer authentication temporarily

Rejected because an unshipped compatibility mode would become a downgrade path
and contradict the accepted proof-of-possession profile.

### Return the external access token as the session

Rejected because the relay would lose participant-instance identity,
monotonic epochs, immediate local revocation and proof-key binding.

### Make bootstrap idempotent

Rejected because replaying a prior secret response requires storing recoverable
session credentials or inventing another client secret. A new valid bootstrap
creates a new bounded session instead.

## Rollout and rollback

Implementation is one compile-time-breaking contract increment across
`httpapi`, runtime composition and their tests. It adds no persistent state and
can be rolled back without data migration. The branch must remain
non-deployable and contains no permissive fallback.

## Primary references

- [RFC 6750, OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- [RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 9068, JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9449, OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 9700, Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
