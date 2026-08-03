# Protocol surface

Protocol 0.1 uses these signal families:

| Flow | Signals |
| --- | --- |
| Presence | `join`, `leave` |
| Work | `claim`, `progress`, `release` |
| Questions | `question`, `answer` |
| Review | `review_request`, `verdict` |
| Transfer | `handoff_offer`, `handoff_accept` |
| Evidence | descriptors and `evidence_verification` |

Events are append-only. Relay receipts bind admitted bytes, identity, channel,
sequence and policy evidence. See the repository [schemas](https://github.com/nomed/yukh-coordination/tree/main/schema)
and normative [RFC-0001](https://github.com/nomed/yukh-coordination/blob/main/.context/rfcs/RFC-0001-protocol-v0.1.md).

Unknown versions, invalid transitions and incomplete histories fail closed.
