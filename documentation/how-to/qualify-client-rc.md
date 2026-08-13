# Qualify the client RC

From the repository root, run:

```sh
.github/scripts/qualify-client-rc.sh
```

It repeats the executable bootstrap, runs the isolated two-session flow, builds
byte-identical Linux `amd64` and `arm64` binaries, and checks their SHA-256
manifest. The synthetic token issuer, TLS endpoint and credentials exist only
inside the tests.

Build only the binaries with:

```sh
.github/scripts/package-client-rc.sh 0.1.0-rc.1 "$PWD/dist"
```

The package contains no configuration, secret or NATS endpoint.
