# Session 2026-08-04 — RFC-0024 offline ceremony design

## Authority and scope

- Governing issue: #147
- Accepted deployment design: RFC-0022
- Accepted clarification: RFC-0024
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

RFC-0024 was explicitly accepted by the project owner. No cryptographic material,
canonical policy artifact, receipt, registry object, namespace, Secret,
workload, listener or request is created. Private custody destinations and
exact server identity remain outside the repository.

## Next boundary

After merge, implement only the execution-forbidden Ceremony A tooling and
private runbook under a new reviewed increment. Execution still requires a new
explicit approval, and RFC-0022 step 5 plus live traffic remain later
independent gates.
