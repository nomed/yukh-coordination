# Qualify the local end-to-end flow

Run the hermetic cross-suite qualification from the repository root:

```sh
.github/scripts/qualify-coordination-e2e.sh
```

The command requires Go 1.26, Node.js 24, and Python 3. It starts one
test-owned HTTPS/SSE relay on an ephemeral loopback port and two isolated
client subprocesses representing four client identities. The relay uses the
in-memory adapter; NATS, cloud services, credentials, and external traffic are
not used.

The scenario publishes and replays 15 signed records covering join, claim,
progress, review, handoff, successor claim, release, and leave. It also reads
join records through SSE and proves that a handoff acceptance from the wrong
participant is rejected with `YKC-CONFLICT-001` without changing the
transcript.

The Go test owns the listener, TLS material, signing key, processes, and memory
store. Test cleanup closes the stream and listener, stops the relay, and waits
for both subprocesses. A successful run ends with:

```text
coordination-e2e: PASS processes=3 clients=4 transport=HTTPS+SSE storage=memory ports=1-ephemeral transcript_records=15 fence=wrong-recipient
```

This is synthetic repository qualification only. It does not authorize
deployment, publication, live traffic, provider execution, or production use.
