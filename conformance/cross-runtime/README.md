# Cross-runtime projection gate

The three common transcripts cover a single claim, conflict followed by an
explicit release, and an accepted handoff in an incomplete/redacted transcript.
They are adapted without semantic rewriting to the independent Python and
JavaScript replay CLIs.

`run.py` compares the raw canonical projection stdout byte for byte. It then
checks the committed canonical projection and SHA-256 digest. Wrapper metadata
from the JavaScript engine is excluded by `js_adapter.mjs`; canonicalization is
still performed by the JavaScript implementation itself.

```bash
python3 conformance/cross-runtime/generate.py
python3 conformance/cross-runtime/run.py --update  # accountable fixture update
python3 conformance/cross-runtime/run.py
```

Any semantic divergence fails the gate. The runner does not normalize fields,
ordering, diagnostics, state, lifecycle, or canonical bytes.
