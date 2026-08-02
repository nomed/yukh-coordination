# Protocol v0.1 core conformance corpus

This directory qualifies the client-neutral wire contract from RFC-0001 Draft.
It does not accept the RFC, implement a relay, authenticate identities, or prove
the independent second runtime required by issue #4.

## Contents

- `fixtures/positive`: one valid event for every foundation signal plus closed
  evidence, channel metadata, receipt, and projection examples;
- `fixtures/negative`: a missing-required-field case for every signal and
  cross-envelope/semantic failures;
- `canonical`: JCS inputs, exact bytes, SHA-256 digests, and applicable frozen
  domain digests for event, channel metadata, evidence descriptor/set, receipt,
  receipt signature preimage, and diagnostics;
- `SHA256SUMS`: immutable byte manifest for all corpus and runner inputs;
- `validate.py`: standard-library schema subset, reference resolver, semantic
  checks, JCS canonicalizer, fixture runner, and manifest verifier;
- `generate.py`: deterministic corpus regeneration tool.

## Repeatable validation

```bash
python3 conformance/generate.py
python3 conformance/validate.py --check-manifest
git diff --exit-code
```

The generator intentionally rewrites only generated fixtures, canonical vectors,
their indexes, and `SHA256SUMS`. A clean diff after regeneration proves the
checked-in corpus is reproducible.

The validator uses no third-party package. Its schema engine implements the
Draft 2020-12 keywords used by this repository; it is not presented as a general
JSON Schema implementation. Issue #4 still requires validation by a conforming
independent JSON Schema implementation and a second language/runtime.
