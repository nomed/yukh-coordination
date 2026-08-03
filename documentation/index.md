# Make isolated work legible

Yukh Coordination records claims, progress, questions, reviews and explicit
handoffs in a replayable protocol. It does not choose who may act.

!!! warning "Foundation"

    Coordination is not production-ready. No public relay or client release is
    installable. The offline replayer and conformance corpus are usable now.

## First useful result

Clone the repository and replay a checked-in transcript. The deterministic
projection shows its current claim state and completeness.

[Replay the first transcript](tutorials/first-replay.md){ .md-button .md-button--primary }
[Read the protocol surface](reference/protocol.md){ .md-button }

## What it owns

Coordination makes cross-session activity observable. Project authority stays
external; capability authority belongs to systems such as Yukh MCP; delivery
state belongs to systems such as Yukh Projects.
