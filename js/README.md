# Independent JavaScript replay

This dependency-free Node implementation derives the v0.1 work projection from
an offline transcript. It does not import or invoke the Python implementation,
relay code, network clients, or schema libraries.

Input is a JSON object containing transcript metadata and `records`. Each record
contains `event`, `receipt`, and `receipt_verified`. `receipt_verified` is the
result of the transcript exporter's cryptographic receipt verification; this
replayer treats any value other than `true` as incomplete. It independently
recomputes each event JCS digest and all deterministic projection semantics.

```sh
npm test
npm run replay -- --input transcript.json --work https://example.test/issues/42 --pretty
```

For JSONL, the first line is a transcript header with `"kind":"transcript"`;
remaining lines are records with optional `"kind":"record"`. File order is not
semantic: receipt sequence determines relay-local replay order.
