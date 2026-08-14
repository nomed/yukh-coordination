# Qualify the client RC

From the repository root, run:

```sh
.github/scripts/qualify-client-rc.sh
```

It repeats the executable bootstrap, runs the isolated two-session flow, builds
byte-identical Linux and macOS binaries for `amd64` and `arm64`, and checks
their SHA-256 manifest. The synthetic token issuer, TLS endpoint and credentials
exist only inside the tests.

On macOS, install Go 1.26, Node.js 24, Python 3 and `nats-server` 2.12, then run:

```sh
.github/scripts/qualify-macos-local.sh
```

This starts disposable local JetStream processes from the tests. To exercise
the standalone coordinator with Docker Compose and native Mac clients, follow
[Run the local preview](run-local-preview.md).

Build only the binaries with:

```sh
.github/scripts/package-client-rc.sh 0.1.0-rc.2 "$PWD/dist"
```

The package contains no configuration, secret or NATS endpoint.
