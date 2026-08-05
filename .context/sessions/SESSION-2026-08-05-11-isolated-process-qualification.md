# Session: isolated-process qualification

- Date: 2026-08-05
- Governing issue: #7
- Accepted decision: RFC-0013

## Outcome

Two operating-system processes completed the four-agent scenario through the
real TLS handler. The implementation session owned agents A and B; the
independent review session owned C and D. Each received only its own synthetic
credentials and learned cross-session state by verified transcript replay.

Both replays produced the committed 15-record sanitized fixture with digest
`sha-256:8409d018160f3db0fc885185df9fc7baae78cee27e7860254823a1aed095d995`.
The fixture preserves sequence, signal type and participant while excluding
generated identifiers, receipts, credentials and transport data.

## Reproduce

Run `go test ./internal/relay/runtime -run TestTwoIsolatedCLIProcesses -count=1`.

## Boundary

The qualification uses a hermetic test relay, test-only TLS certificate and
memory Store. It authorizes neither deployment nor Matrix or production use.
