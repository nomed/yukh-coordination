# SQLite reference adapter

This package is the durable single-node implementation of the neutral relay
store port. It is qualification evidence for issue #5, not an operated service
or production topology.

## Frozen candidate profile

- Go module: `modernc.org/sqlite` at the exact version in `go.mod` and `go.sum`;
- SQLite journal mode: WAL;
- durability: `synchronous=FULL`;
- referential integrity: foreign keys enabled;
- writer contention bound: 5-second SQLite busy timeout;
- process model: one database connection, serializing sequence allocation;
- schema: STRICT tables with `PRAGMA user_version=4`;
- tenant/channel predicates on every identity, append and replay query.

Channel identity is immutable across transcript epochs. Event IDs are unique
within a tenant/channel identity across all epochs. Receipt IDs are globally
unique. Event material, bindings, sequence, digest, receipt identity and
unsigned receipt preimage commit in one `BEGIN IMMEDIATE` transaction. Receipt
signatures are produced outside the database and attached in a second exact,
idempotent transaction; a different signature or preimage is a collision.
Canonical channel metadata, its domain-separated digest and transcript
lifecycle are persisted per epoch and exposed through the neutral lookup port.
Migrated rows without those formerly unavailable fields fail closed.

`LifecyclePreparation` is a separately capability-segregated adapter. It
accepts only policies already verified by the offline manifest provider,
requires their digest and epoch to match immutable channel metadata, and
persists policy binding, operation intent, export evidence, marker and receipt
preimage. Marker persistence and the transcript admission fence commit in the
same `BEGIN IMMEDIATE` transaction. The adapter never removes payload bytes,
attaches lifecycle signatures, records backup receipts or completes an
operation; those destructive capabilities are intentionally outside this
increment. The lifecycle high-water reference is the exact signed receipt ID
at the transcript high-water sequence.

Any failed `COMMIT` is reported as `relay.ErrCommitIndeterminate`; callers must
not manufacture a replacement append. An exact retry resolves the outcome by
the original event ID and canonical bytes.

## Recovery evidence

The tests cover clean close/reopen and abrupt process termination:

- exit after commit preserves the exact record and sequence;
- exit during record preparation rolls back and does not consume a sequence;
- exact retries after restart return the original receipt identity;
- concurrent appends remain gap-free;
- changed bytes and cross-epoch ID reuse collide;
- tenant-scoped replay does not cross identity boundaries.

The database file and its `-wal`/`-shm` sidecars form one live SQLite failure
domain. Copying only the main file while the database is open is not a valid
backup procedure. Backup, restore, retention and deletion qualification remain
open gates of issue #5.
