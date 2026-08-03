# SESSION-2026-08-03-08: Stateful admission

- Governing issue: #5
- Pull request: pending
- Status: Active

## Objective

Enforce RFC-0001 state-dependent admission in the same persistence transaction
that allocates sequence and commits an accepted record.

## Implemented

- `AdmissionView` and checked append on the neutral Store port;
- memory lock and SQLite `BEGIN IMMEDIATE` implementations of the same atomic
  validation boundary;
- causation, scope, correlation and typed-parent resolution;
- claim-generation reuse, active-claim and active-offer bounds;
- current-parent claim lifecycle validation;
- recipient-bound, single-use handoff acceptance CAS and successor binding;
- review evidence-set and evidence-descriptor verification binding;
- stable HTTP mapping for resource and transition failures;
- concurrency and transition regression tests.

## Boundary retained

This increment adds no broker, provider, executable or deployment. Retention
mutation, backup/restore qualification and operational security audit remain
separate issue #5 gates.

## Next

Publish and qualify the stateful admission increment, then begin the JetStream
adapter against the now-complete application/store boundary.
