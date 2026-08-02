# Cross-runtime projection gate

Common transcripts cover claim, conflict/release, handoff and incomplete
lifecycle, multiple offers, all evidence-verification outcomes, exact duplicate,
ID/receipt/sequence collisions, CAS failures, receipt/high-water verification,
and sequence gaps. They are adapted without semantic rewriting to the
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
bytes. Admission/transition failures use the same closed error codes in both
runtime families. The committed gate covers 13 byte-identical projections and
10 identical typed rejection outcomes, including multiple chained offers,
evidence bindings, duplicate/collision behavior, CAS failures, verifier status,
sequence gaps, and inactive transcript lifecycle.
