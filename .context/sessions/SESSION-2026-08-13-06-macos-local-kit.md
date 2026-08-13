# Session 2026-08-13 — macOS local kit

Issue #6 extends the reproducible client package with macOS `amd64` and `arm64`
binaries and adds one local macOS qualification entry point. The entry point
uses a native disposable `nats-server` for real JetStream adapter tests, then
runs the hermetic HTTPS/SSE multi-session flow and complete client RC checks.

There is no standalone coordinator executable yet. The macOS kit therefore
labels the coordinator as a test-owned runtime and does not claim a complete
Docker Compose deployment. NATS remains server-side and no endpoint or
credential enters the client package.
