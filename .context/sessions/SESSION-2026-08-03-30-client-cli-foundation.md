# Session: RFC-0013 client and CLI foundation

- Date: 2026-08-03
- Governing issue: #6
- Pull request: pending
- Accepted decision: RFC-0013
- Scope: first read-only implementation increment

## Outcome

Implemented the provider-neutral read foundation without adding a process
executable. `internal/client` performs bounded HTTPS replay with explicit
configuration, a mandatory request-authorizer port and a mandatory receipt
verifier port. It rejects redirects, target mutation, non-canonical pages,
metadata mismatch, sequence gaps, changed event digests, receipt-binding
failure, unsigned or untrusted receipts and incomplete boundaries.

Replay pagination advances only from the last verified sequence. `work inspect`
derives visible active claims, participant instances, latest progress and
handoff offers from the verified transcript. Concurrent claims remain
`conflicting`; the client never elects an owner or infers release from absence.

`internal/clientcli` defines explicit `events replay`, `work inspect` and
`version` parsing plus one closed JSON document and the accepted stable exit
classes. It reads no provider environment, git state, token or credential file.

## Qualification

- real RFC-0009 HTTP/TLS handler with explicit authentication, authorization,
  application and receipt-verifier fakes;
- multi-page replay and concurrent-claim inspection;
- incomplete boundary, changed receipt and target-substitution negatives;
- canonical numeric CLI arguments and sanitized failure output;
- full Go race suite with NATS Server 2.12.0;
- `go vet ./...`, repository structure and generated conformance checks;
- 14 independent JavaScript replay tests.

## Explicit boundary

No `cmd/`, server binary, DPoP key implementation, credential-store adapter,
SSE watch, event mutation, deployment configuration or provider-specific
integration is included. Those remain separately reviewable RFC-0013 increments.

## Next step

Owner review of this foundation. After acceptance, the next bounded increment is
DPoP request signing and operating-system credential-store ports with no
plaintext fallback; it must not be combined with watch or event mutation.
