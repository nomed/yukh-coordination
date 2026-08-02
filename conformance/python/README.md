# Python replay/projection implementation

This is an independent Python 3 standard-library implementation of the
RFC-0001 replay and closed work-projection rules. It shares no code with the
reference relay or the other conformance runtime.

It consumes already admitted transcript records. It validates canonical event
digests, receipt/event/channel bindings, contiguous sequencing, idempotent
duplicates and collisions, causal/correlation scope, claim generations,
release and handoff transitions, recipient instances, evidence-verification
bindings, resource limits, and completeness/lifecycle effects. Receipt
signature cryptography, authentication, ACL admission, network transport,
relay persistence, and restricted security audit are deliberately outside this
projection engine; their independent fixtures remain part of the wider #4/#5
qualification boundary.

## Input

JSON uses this wrapper:

```json
{
  "metadata": {
    "tenant_id": "tenant:example",
    "channel_id": "channel:project-release",
    "channel_uri": "https://coord.example/channels/project-release"
  },
  "transcript_epoch": 0,
  "completeness": "complete",
  "origin_sequence": 1,
  "lifecycle": "active",
  "high_water_sequence": 2,
  "high_water_receipt_verified": true,
  "records": [
    {"event": {}, "receipt": {}, "receipt_verified": true}
  ]
}
```

For JSONL, the first nonempty line is `{"transcript": <wrapper without
records>}` and every following line is one event/receipt record.

The adapter consumes the same `receipt_verified` and
`high_water_receipt_verified` evidence as the independent JavaScript runtime.
The engine derives completeness from deterministic reasons rather than trusting
the declared label. Forensic reasons are sorted and closed:

- `unverified-receipt`;
- `unverified-high-water`;
- `sequence-gap`;
- `record-after-high-water`;
- `non-active-lifecycle`.

Admission-impossible observations fail with the normative RFC/problem code:
`ID_COLLISION` for one event ID with changed canonical bytes;
`INVALID_RECEIPT` for a changed receipt or reused sequence;
`HANDOFF_PRECONDITION_FAILED` for an invalid offer or failed acceptance CAS;
`INVALID_REFERENCE` for a missing or ambiguous evidence descriptor; and
`INVALID_PAYLOAD` for an invalid evidence outcome or unequal bound fields.
Internal forensic labels do not replace these public codes. An exact duplicate
with identical canonical event bytes and receipt is idempotent and adds no
reason. Input record order is advisory; replay uses receipt sequence.

## CLI and tests

```bash
python3 conformance/python/yukh_projection.py transcript.json --work-uri https://example.test/issues/1
python3 -m unittest discover -s conformance/python -p 'test_*.py' -v
```

Output is canonical JSON. Without `--work-uri`, the CLI emits projections
sorted by exact work URI; with it, the output is one object matching the closed
projection schema.
