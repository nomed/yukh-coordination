# Session: client bootstrap saga

- Date: 2026-08-05
- Governing issue: #6
- Accepted decision: RFC-0014

## Outcome

The neutral client now executes the accepted bootstrap saga: provision signer,
acquire its bound external token, request a relay session, persist it with CAS,
then reload and verify the exact signer binding.

## Next

Implement the HTTPS bootstrap exchange and an explicit workstation root-key
adapter, then connect both to the executable.
