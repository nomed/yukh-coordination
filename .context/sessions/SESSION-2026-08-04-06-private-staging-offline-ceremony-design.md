# Session 2026-08-04 — RFC-0024 offline ceremony design

## Authority and scope

- Governing issue: #147
- Accepted deployment design: RFC-0022
- Proposed clarification: RFC-0024 Draft
- Operator packet: #136, still `REJECT_INCOMPLETE`

## Delivered proposal

- identifies the impossible ordering between a pre-step-5 signed-registration
  digest and a step-5-only, <=15-minute token/DPoP identity;
- proposes a separately approved durable offline trust/policy ceremony;
- keeps ephemeral token, DPoP and signed registration inside step 5;
- makes the actual signed-registration digest mandatory step-6 evidence;
- defines volatile isolation, encrypted custody, canonical artifacts,
  two logical checkpoints, abort/destruction and redacted receipt boundaries.

## Intentionally incomplete

RFC-0024 is Draft and has not been accepted. No cryptographic material,
canonical policy artifact, receipt, registry object, namespace, Secret,
workload, listener or request is created. Private custody destinations and
exact server identity remain outside the repository.

## Next boundary

Review this proposal and ask the project owner to explicitly accept or revise
RFC-0024. Acceptance would authorize only a separately reviewed implementation
of the ceremony, not execution. Execution would still require a new explicit
approval, and RFC-0022 step 5 plus live traffic remain later independent gates.
