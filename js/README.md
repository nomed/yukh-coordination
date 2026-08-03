# Independent JavaScript replay

This dependency-free Node implementation derives the v0.1 work projection from
an offline transcript. It does not import or invoke the Python implementation,
relay code, network clients, or schema libraries.

Input uses the common cross-runtime object containing `metadata`,
`declared_completeness`, `lifecycle`, origin/high-water fields, and `records`. Each record
contains `event`, `receipt`, and `receipt_verified`. `receipt_verified` is the
result of the transcript exporter's cryptographic receipt verification; this
replayer treats any value other than `true` as incomplete. It independently
recomputes each event JCS digest and all deterministic projection semantics.

Impossible admitted histories fail with a stable error: an event ID with changed
bytes, an exact event with a changed receipt, a reused sequence, an invalid
handoff transition, or a broken evidence binding. Forensic export conditions
such as an unverified receipt/high-water, a gap, post-high-water record, or
non-active lifecycle remain inspectable but produce an incomplete, non-final
projection with frozen reason codes.

```sh
npm test
npm run replay -- --input transcript.json --work https://example.test/issues/42 --pretty
```

The dependency-free coordination-primitives client is bundled deterministically
into `js/dist/primitives-client.mjs`. Regenerate it with
`npm run build:primitives`; CI uses `npm run check:primitives-bundle` to require
byte-identical output and the committed SHA-256 checksum.

For JSONL, the first line is a transcript header with `"kind":"transcript"`;
remaining lines are records with optional `"kind":"record"`. File order is not
semantic: receipt sequence determines relay-local replay order.
