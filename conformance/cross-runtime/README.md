# Cross-runtime projection gate

Common transcripts cover claim, conflict/release, handoff and incomplete
lifecycle, multiple offers, all evidence-verification outcomes, exact duplicate,
ID/receipt/sequence collisions, CAS failures, receipt/high-water verification,
sequence gaps, missing origin, records beyond signed high-water, and redacted or
deleted lifecycle. They are adapted without semantic rewriting to the
independent Python and JavaScript replay CLIs.

`run.py` compares the raw canonical projection stdout byte for byte. It then
checks the committed canonical projection and SHA-256 digest. Wrapper metadata
from the JavaScript engine is excluded by `js_adapter.mjs`; canonicalization is
still performed by the JavaScript implementation itself.

```bash
python3 conformance/cross-runtime/generate.py
python3 conformance/cross-runtime/run.py --update  # accountable fixture update
python3 conformance/cross-runtime/run.py
```

The seven canonical/domain vectors and all valid replay cases compare raw
bytes. Admission/transition failures are fail-closed mapped from asserted engine
codes to the normative public codes: `ID_COLLISION`, `INVALID_RECEIPT`,
`HANDOFF_PRECONDITION_FAILED`, `INVALID_REFERENCE`, and `INVALID_PAYLOAD`.
Unexpected engine codes fail rather than being normalized. The committed gate
covers 16 byte-identical projections and 11 identical typed rejection outcomes,
including zero/ambiguous/mismatched evidence bindings, duplicate/collision
behavior, CAS failures, verifier status, origin/gap/high-water cases, and
inactive transcript lifecycle.
