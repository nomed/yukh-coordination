# Linux Secret Service qualification harness

RFC-0018 (governing issue #68) requires real-service evidence in addition to
the deterministic adapter tests. This harness is supplied for that evidence;
it is **not** evidence that either service has been qualified. No opt-in run
has been recorded with this change.

## GNOME Keyring

From the checkout root, explicitly opt in to the public image/package download
and Docker execution:

```sh
.github/scripts/qualify-linux-secret-service.sh --run-gnome-keyring
```

The harness builds from a pinned Linux `amd64` Go image and a fixed Debian
snapshot, then runs with networking disabled. It creates a private D-Bus
socket, an empty GNOME Keyring home/data directory, a blank-password
disposable `login` keyring and an ephemeral container. The service setup alone
receives its private bus address. The Go test has that environment variable
removed, explicitly dials the private socket, and passes only its resulting
file descriptor to the adapter. All container state, processes and the
temporary image are removed on exit.

The test checks the actual DH transfer/create and reopen path, rejects an
unusable supplied stream even when an ambient bus variable names the private
bus, and locks the exact configured collection before verifying that the
adapter fails without invoking a prompt. It does not issue relay requests,
accept credentials, use host user D-Bus state or retain the generated root
item.

The command prints the pinned image, snapshot, installed package versions and
test names so a reviewer can retain an execution record. A provider lock
operation that returns a prompt is a failure: the harness deliberately does
not invoke `Prompt`.

## KeePassXC

KeePassXC Secret Service needs an explicitly unlocked GUI/daemon and cannot
be safely automated in this headless Docker topology. The following command
prints, then exits with status 2 after, the manual gate:

```sh
.github/scripts/qualify-linux-secret-service.sh --keepassxc-manual
```

Run that printed command only against a dedicated disposable KeePassXC
database and an independently created private D-Bus socket. It requires the
exact selected collection object path and never reads
`DBUS_SESSION_BUS_ADDRESS` to connect the adapter. Destroy the database and
private bus after the test. Do not treat the manual gate, or a skipped prompt
path, as KeePassXC qualification evidence.

## Remaining evidence

This root-key adapter has no root-item deletion operation, so delete behavior
is not exercised here. Service-specific prompt, persistence and deletion
behavior must be recorded from an approved real-service run. Passing GNOME
Keyring does not qualify KeePassXC, nor does either run replace RFC-0018's
remaining deterministic and end-to-end qualification gates.
