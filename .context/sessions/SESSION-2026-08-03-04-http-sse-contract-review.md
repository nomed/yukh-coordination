# SESSION-2026-08-03-04: HTTP/SSE contract review

- Governing issue: #5
- Pull request: #19
- Status: Active

## Objective

Define the public HTTP/SSE compatibility and security boundary before exposing
the qualified relay implementation.

## Work completed

- drafted binding RFC-0004 from accepted protocol and security requirements;
- separated transport version `v1` from protocol `specversion` 0.1;
- defined append, bounded replay and live stream resources;
- froze proposed authentication/admission order and non-enumerating denial;
- defined cursor, reconnect, backpressure and unsigned-boundary behavior.

## Evidence and validation

The proposal is aligned with RFC 9110, RFC 9457, RFC 6750 and the WHATWG SSE
format. Executable handler evidence is intentionally gated on owner acceptance
of the public contract.

## Decisions discovered

SSE must stop at an unsigned receipt boundary rather than skip it. Tenant
identity must never appear as a client-selected path or query input. Native
browser `EventSource` convenience is not a v1 goal because authenticated agent
clients need explicit Authorization headers.

## Context impact

RFC-0004 is Proposed and therefore non-authoritative. RFC-0001 through RFC-0003
and the threat model continue to govern.

## Risks and unresolved work

The endpoint shape, replay representation, SSE lifetime and problem vocabulary
require owner review. OpenAPI and AsyncAPI follow executable agreement rather
than preceding it.
