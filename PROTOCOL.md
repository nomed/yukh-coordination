# Yukh Coordination Protocol — foundation draft

Status: **Draft 0.1**. This document is a design input, not an accepted compatibility commitment.

## Model

- **Channel:** named coordination scope for one project or bounded outcome.
- **Participant:** a person, session, or agent identity visible in a channel.
- **Work item:** external stable reference to a bounded outcome.
- **Claim:** participant assertion of current execution ownership over a work item.
- **Signal:** immutable event published to a channel.
- **Evidence:** immutable or content-addressed reference supporting a statement.
- **Handoff:** explicit offer and acceptance of responsibility.

## Envelope

Every durable signal uses a versioned envelope:

```json
{
  "specversion": "0.1",
  "id": "01J...",
  "channel": "project-release",
  "type": "question",
  "time": "2026-08-02T16:00:00Z",
  "participant": {
    "id": "session:wave-2",
    "kind": "session",
    "display": "wave-2"
  },
  "work": {
    "uri": "https://github.com/example/project/issues/42"
  },
  "correlation": {
    "id": "01J..."
  },
  "data": {},
  "evidence": [
    {
      "uri": "https://github.com/example/project/actions/runs/123",
      "digest": "sha256:...",
      "mediaType": "application/json"
    }
  ]
}
```

## Foundation signal types

| Type | Purpose | Durable |
|---|---|---:|
| `join` | announce a participant entering the channel | yes |
| `presence` | report current availability without transferring authority | optional |
| `claim` | assert bounded ownership of a work item | yes |
| `progress` | publish a material state update | yes |
| `question` | request a correlated answer | yes |
| `answer` | answer one question by correlation ID | yes |
| `review_request` | request independent evaluation of referenced evidence | yes |
| `verdict` | publish `pass`, `fail`, or `inconclusive` with evidence | yes |
| `handoff_offer` | offer explicit transfer to a named participant | yes |
| `handoff_accept` | accept one offer and its stated evidence boundary | yes |
| `release` | relinquish a claim without transferring it | yes |
| `leave` | announce departure; does not implicitly release claims | yes |

## Claim semantics

- A claim is scoped to one canonical work URI.
- The relay may detect competing claims but does not decide project authority.
- A winner requires an external governance rule or an accepted compare-and-set policy.
- Expiry may mark a claim stale; it must not silently release or transfer ownership.
- Release, takeover, and handoff are distinct events.

## Handoff semantics

Handoff is a two-event protocol:

1. `handoff_offer` names the intended recipient, work boundary, current state, evidence, unresolved risks, and requested next action.
2. `handoff_accept` references the offer and confirms the accepted boundary.

Until acceptance, the original participant remains the observable owner. Timeout never implies acceptance.

## Evidence

Evidence entries must use stable URIs. A digest is required when the referenced content can change. Secrets, raw credentials, private prompts, and unrestricted logs must not be embedded in signals.

## Open decisions

- participant identity and authentication;
- channel authorization and tenancy;
- exact canonical serialization and signatures;
- competing-claim compare-and-set semantics;
- retention, redaction, and privacy;
- relay federation and offline replay;
- delivery guarantees and ordering boundaries.
