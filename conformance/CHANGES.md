# Conformance-discovered contract corrections

## 2026-08-02 — envelope property capacity

Issue #4 proved that `maxProperties: 12` contradicted the required shape of a
non-root work event: the ten always-required fields plus `work`,
`correlation_id`, and `causation_id` total 13.

The accountable correction changes only `maxProperties` from 12 to 13. A full
13-property child event is positive evidence and a 14-property event is a
negative fixture. No field, signal, extension, or compatibility behavior was
otherwise enlarged.
