# Yukh Coordination conformance corpus

This directory qualifies byte-stable Yukh Coordination contracts. It contains
the client-neutral protocol corpus from RFC-0001 and the independent canonical
security-audit vectors from RFC-0011. It does not accept an RFC, authorize an
operated service or turn local audit evidence into external transparency.

## Contents

- `fixtures/positive`: one valid event for every foundation signal plus closed
  evidence, channel metadata, receipt, and projection examples;
- `fixtures/negative`: a missing-required-field case for every signal and
  cross-envelope/semantic failures;
- `canonical`: JCS inputs, exact bytes, SHA-256 digests, and applicable frozen
  domain digests for event, channel metadata, evidence descriptor/set, receipt,
  receipt signature preimage, diagnostics, every closed security-audit
  operation shape and receipt, independent
  Merkle roots/proofs, audit checkpoints, verification-key statements and
  signed two-database recovery manifests;
- `SHA256SUMS`: immutable byte manifest for all corpus and runner inputs;
- `validate.py`: standard-library schema subset, reference resolver, semantic
  checks, JCS canonicalizer, fixture runner, and manifest verifier;
- `generate.py`: deterministic corpus regeneration tool.
- `standards-schema.py`: independent pinned `jsonschema` Draft 2020-12 gate;
- `signatures`: fixed RFC 8032-derived receipt, audit-checkpoint and recovery
  manifest signatures with an independent OpenSSL verifier.

The embedded `schema/test-vectors/suite-preview-rfc-0025-1.json` fixture
separately freezes the execution-forbidden RFC-0025 manifest, Effect A/B
authority derivations, negative reuse outcomes and public-evidence bytes. Go
and standards-schema tests consume it without starting a process or making a
network call.

## Repeatable validation

```bash
python3 conformance/generate.py
python3 conformance/validate.py --check-manifest
python3 conformance/standards-schema.py
python3 conformance/signatures/verify.py
python3 conformance/cross-runtime/run.py
git diff --exit-code
```

The generator intentionally rewrites only generated fixtures, canonical vectors,
their indexes, and `SHA256SUMS`. A clean diff after regeneration proves the
checked-in corpus is reproducible.

The validator uses no third-party package. Its schema engine implements the
Draft 2020-12 keywords used by this repository; it is not presented as a general
JSON Schema implementation. Independent validation is now supplied by the
installed standards-conforming `jsonschema` 4.10.3 runtime, pinned in
`standards-requirements.txt`.

The independent Python and JavaScript replay engines are joined by the
[`cross-runtime`](cross-runtime/README.md) gate. Common transcripts and committed
outputs prove byte-identical canonical work projections across both runtimes.
