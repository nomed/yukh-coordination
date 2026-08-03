# SQLite identity registry

This adapter owns the second RFC-0010 increment. It is a separate SQLite
database and never adds identity tables to the event store.

Its narrow operations implement:

- pending session reservation with atomic proof replay and epoch allocation;
- idempotent activation only after the later audit composition supplies a
  receipt;
- active-session lookup with constant-time digest and DPoP binding checks;
- authentication proof reservation in the same immediate transaction;
- exact expected-state revocation and race-free inactive signals;
- bounded expiry scheduling and proof cleanup;
- persistent wall-clock and restore fencing with monotonic epoch floors;
- one atomic, complete and sorted recovery snapshot of database identity,
  wall-clock high-water and every principal epoch floor.

The adapter stores digests, derived identities and closed references only. It
never stores a token, proof, JWT, JWK, external subject, arbitrary claims or
audit payload. Checkpoint and recovery verification belong to the separate
audit security domain; `ApplyRestoreFloors` accepts only its already-verified
closed plan and durable receipt. Runtime ordering and the restore audit record
remain RFC-0011 step 5.
