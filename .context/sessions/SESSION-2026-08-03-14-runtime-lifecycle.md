# Session: Relay runtime lifecycle

- Date: 2026-08-03
- Governing issue: #5
- Governing RFC: RFC-0007
- Branch: `agent/relay-runtime-lifecycle`

## Outcome

Implemented `internal/relay/runtime` as the typed composition root authorized by
RFC-0007. It assembles the existing handler, application, append service,
validator, Store, subscription source and mandatory provider interfaces without
selecting products or reading external configuration.

`Run` owns a one-shot monotonic lifecycle, derives every request context from
the parent lifecycle, performs bounded graceful shutdown with forced close,
and closes uniquely named owned resources once in reverse registration order.
Lifecycle errors preserve `errors.Is` identity while redacting provider error
text.

## Evidence

- real TLS request traverses authentication, authorization, protocol
  validation, signing and durable Store append;
- active SSE terminates when the runtime context is cancelled;
- blocked provider forces shutdown at the explicit deadline;
- serve, shutdown and multiple resource failures are joined and redacted;
- concurrent cancellation and serving failure close resources exactly once;
- every required dependency and lifecycle limit fails closed when absent or
  invalid, including typed-nil interfaces and duplicate resource names;
- repeated runtime tests, complete real-JetStream Go suite, `go vet` and the
  repository structure check pass.

## Boundary

No binary, provider, environment parsing, secret loading, product selection,
operational endpoint or deployment configuration was added. The next decision
gate is the provider profile required by RFC-0007.
