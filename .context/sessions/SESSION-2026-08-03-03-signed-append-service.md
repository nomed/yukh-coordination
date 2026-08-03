# SESSION-2026-08-03-03: Signed append service

- Governing issue: #5
- Pull request: pending
- Status: Active

## Objective

Close the trust-boundary gap between durable append and public acknowledgement
before exposing the relay through HTTP.

## Work completed

- added exact, idempotent receipt-signature attachment to the store port;
- migrated the SQLite schema from version 1 to version 2;
- added a transport-neutral signed-append service;
- made key selection a pre-transaction requirement for new appends;
- made exact retries recover committed unsigned records using their persisted
  receipt preimage rather than selecting a replacement key.

## Evidence and validation

- memory and SQLite signature attachment contract tests pass;
- changed signatures and changed preimages collide;
- signer selection failure commits nothing;
- signing failure returns no success and leaves a recoverable append;
- recovery after SQLite close/reopen signs the original receipt identity.

## Decisions discovered

The accepted RFC-0002 ACK boundary must be implemented before the HTTP append
endpoint. No new architecture decision is required.

## Context impact

The HTTP/SSE binding remains the next increment. Endpoint paths and cursor
semantics still require their component RFC before becoming a public contract.

## Risks and unresolved work

The current signer is a port exercised with deterministic fakes. Ed25519 key
registry and lifecycle implementation, permanent-key-loss evidence, and HTTP
error mapping remain issue #5 gates.
