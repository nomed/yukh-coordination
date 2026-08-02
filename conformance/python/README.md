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
  "lifecycle": "active",
  "high_water_sequence": 2,
  "records": [
    {"event": {}, "receipt": {}}
  ]
}
```

For JSONL, the first nonempty line is `{"transcript": <wrapper without
records>}` and every following line is one event/receipt record.

The transcript producer is responsible for setting `completeness` to
`incomplete` when receipt signature or external transcript verification fails.
The engine independently downgrades it when sequences are not exactly
contiguous from origin through the declared high-water mark.

## CLI and tests

```bash
python3 conformance/python/yukh_projection.py transcript.json --work-uri https://example.test/issues/1
python3 -m unittest discover -s conformance/python -p 'test_*.py' -v
```

Output is canonical JSON. Without `--work-uri`, the CLI emits projections
sorted by exact work URI; with it, the output is one object matching the closed
projection schema.
