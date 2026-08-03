# Session: RFC-0012 post-merge qualification

- Date: 2026-08-03
- Governing issue: #43
- Pull request: #46
- Accepted decision: RFC-0012
- Scope: post-merge qualification and durable-state reconciliation

## Outcome

Pull request #46 was merged externally as `b7eaa28` while the planned owner
review was beginning. The merge was not reverted or rewritten. A post-merge
review found no blocking defect and confirmed that the implementation remains
inside the RFC-0012 boundary.

The provider-neutral nonce and fenced-lease ports live under
`internal/coordination`. The JetStream adapter owns only the two versioned KV
buckets. It does not modify the RFC-0006 relay Store, split a relay transaction,
or introduce approval, GitHub mutation, deployment or live-apply authority.

Nonce consumption uses create-if-absent replay protection. Lease acquisition,
renewal and release use revision CAS with monotonic fencing tokens. Ambiguous
acknowledgements are reconciled with one exact read and fail closed when the
committed value cannot be proven. Retention must be strictly greater than the
maximum lifetime plus the declared replay-safety window. Existing bucket
configuration and recovery epoch are admitted only on an exact profile match.

## Qualification

- GitHub Actions run `30805041572`: passed;
- `YUKH_NATS_SERVER=<nats-server-v2.12.0> go test -race ./...`: passed;
- `go test ./...`: passed;
- `go vet ./...`: passed;
- `govulncheck ./...`: no reachable vulnerabilities;
- `node --test js/test/*.test.mjs`: 14 tests passed;
- `python3 conformance/generate.py --check`: passed;
- repository structure and `git diff --check`: passed.

## Boundary and next step

RFC-0012 storage delivery is complete and issue #43 is closed. The next
increment belongs in `yukh-projects`: specify the first controlled-apply
consumer against these neutral ports. Consumer policy, approval verification,
GitHub credentials and protected mutations must not move into Coordination.
