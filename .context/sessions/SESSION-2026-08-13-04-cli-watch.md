# Session 2026-08-13 — CLI watch

Issue #6 adds the missing `events watch` executable path. The client performs a
bounded verified replay, opens the authenticated HTTPS SSE stream from the last
verified sequence, accepts only the closed canonical record frame, verifies
event/receipt binding and signature, and emits each record as one JSON object.

The executable requires a bounded watch deadline. Gaps, malformed frames,
incomplete boundaries, unknown fields, invalid receipts and transport ambiguity
fail closed. JetStream remains a server-side implementation detail and no NATS
endpoint or credential crosses into the client.
