# Session 2026-08-13 — client RC package

Issue #6 adds deterministic Linux `amd64` and `arm64` client packaging plus one
bounded RC qualification command. It repeats the executable HTTPS bootstrap,
runs the isolated two-session flow, compares independent builds and verifies
the checksum manifest.

The synthetic issuer, TLS endpoint and credentials remain test-owned and are
not packaged. Candidate binaries contain no configuration, secret or NATS
endpoint. Publishing a GitHub release remains a separate release decision.
