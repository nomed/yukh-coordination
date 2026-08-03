# Repository operating contract

This repository is developed by humans and agents across providers and
sessions. Before planning or editing:

1. read `.context/README.md` and `.context/manifest.yaml`;
2. read `.context/current.md` for navigation only;
3. load the accepted ADRs, RFCs and security records relevant to the task;
4. link implementation work to its governing issue and pull request.

`.context/` is the sole durable engineering-memory root. Do not create parallel
ADR, RFC, security, session or handoff trees elsewhere. Session summaries and
handoffs are non-authoritative; they cannot change accepted architecture.

The top-level directory map in `.context/README.md` is closed. Do not add a
top-level directory without an accepted decision that updates the map and the
repository-structure check in the same change. Never restore compatibility
copies under `docs/` or a root `test/` directory.

Keep provider-specific adapters outside the neutral relay core. Never commit
credentials, private reasoning, unrestricted transcripts, generated scratch
output or adopter-specific sensitive data.
