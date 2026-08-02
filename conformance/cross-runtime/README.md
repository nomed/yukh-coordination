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

The seven canonical/domain vectors and all cases expected to converge compare
raw bytes. Admission/transition cases with deliberately different engine APIs
use per-runtime expected outcomes. These make gaps visible rather than silently
normalizing them. At this revision, Python rejects a second current handoff
offer because it advances its lifecycle parent while JavaScript accepts the
normative multi-offer projection; Python also lacks the JavaScript verifier
status inputs; JavaScript currently does not enforce evidence descriptor
bindings; and JavaScript reports several invalid transitions as incomplete
projection reasons where Python returns a typed error. These gaps are committed
as 13 explicit per-runtime outcome specifications, alongside 10 byte-identical
projection cases and seven byte-identical canonical/domain vectors.
