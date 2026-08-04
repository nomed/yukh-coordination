# Session 2026-08-04 — RFC-0022 reproducible artifact digests

## Authority and scope

- Governing issue: #136
- Accepted design: RFC-0022
- Candidate commit: `d122f31ce6a74dcec97dfcf8095a4447e23ee593`
- Candidate tree: `a59ba3f7ad6018d96f7329710eb593766acda676`
- Operator-packet delivery: commit
  `55306b1c34c09bddc18d26b5c05f839901bcd10b`

## Controlled build evidence

The official Go `1.26.5` Linux AMD64 archive was downloaded directly from
`go.dev` and matched its published SHA-256:

`5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`

The exact detached candidate was built twice per executable with
`CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, an empty Go build ID and the
reviewed embedded revision. Both pairs were byte-identical.

| Artifact | SHA-256 |
|---|---|
| `yukh-coordination-primitives` | `00a9aacbb6c308d4a168cc087c2c396680edab55bb682458872056abce10f000` |
| `yukh-coordination-primitives-bootstrap` | `edcdc8d99b26799795c3d5d7551b636d5009933e81683e512676e170852a55df` |

The artifacts remained outside the repository in an isolated temporary build
directory. No executable was installed or run against infrastructure.

## Intentionally incomplete

This is one local controlled reproducer, not the independent security-reviewer
reproduction required for a complete packet. Private role assignments,
listener/trust/policy digests, exact limits, epoch evidence, filesystem
outcomes, descriptor-purpose review, rollback identifiers and synthetic-window
proposal remain `PENDING`.

## Next boundary

An independent accountable reviewer must reproduce both artifact digests and
the operator must supply the remaining private evidence. Until every pending
field passes review, the packet decision remains `REJECT_INCOMPLETE` and no
RFC-0022 step-5 approval may be requested.
