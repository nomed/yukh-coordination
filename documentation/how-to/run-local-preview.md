# Run the local preview

Requirements: macOS, Docker Desktop, Go 1.26, Python 3 and OpenSSL.

Start the sandbox from a clean Coordination checkout:

```sh
.github/scripts/yukh-local-preview-macos.sh up
.github/scripts/yukh-local-agent.py agent-a session bootstrap
.github/scripts/yukh-local-agent.py agent-b session bootstrap
```

Publish from one terminal:

```sh
printf '%s\n' '{"capabilities":["publish","replay"],"session_label":"agent-a","status":"available"}' |
  .github/scripts/yukh-local-agent.py agent-a session join
```

Read from the other:

```sh
.github/scripts/yukh-local-agent.py agent-b events replay
```

Remove the sandbox and its local credentials:

```sh
.github/scripts/yukh-local-preview-macos.sh down
```

JetStream, the coordinator and the bootstrap authority run inside the isolated
Compose network. Only the two TLS endpoints bind to `127.0.0.1`; clients run
natively on the Mac.
