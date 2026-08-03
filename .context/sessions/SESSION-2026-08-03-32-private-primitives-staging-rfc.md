# Session: Private primitives staging profile proposal

- Governing issue: #90
- Pull request: pending
- Status: proposal ready for owner review

## Objective

Define the first complete deployable Coordination primitives profile required
for a real but non-production MCP consumer connection.

## Work completed

Proposed RFC-0022 for one Linux process on a private staging network with direct
TLS, loopback operations, one short-lived descriptor-delivered DPoP workload
credential, signed fixed-action registration, durable proof replay, accepted
JetStream KV stores, capability sealing and mandatory security audit.

## Evidence and validation

The proposal preserves the immutable RFC-0015 wire surface and RFC-0021
contention semantics. It uses no relay session or transcript component and
introduces no endpoint, credential, infrastructure or executable source.

## Decisions discovered

The current primitives implementation is a qualified handler, not a deployable
service. A consumer-side configuration alone cannot create a real connection;
server authentication, authorization, TLS, audit, custody, storage and
operations must first be composed under an accepted profile.

## Context impact

Adds draft RFC-0022 and its proposed threat-model impact. No accepted record is
modified.

## Risks and unresolved work

Owner acceptance is required before implementation. Provisioning and live
qualification retain two later explicit approval gates. Production remains out
of scope and requires a superseding profile.
