# Yukh Coordination context system

`.context/` is the repository-owned durable memory for humans and agents. It is
the sole home of component decisions, RFCs, security models, session summaries
and handoffs. Chat history and tool-local memory are never authoritative.

## Precedence

1. current explicit human instruction;
2. accepted decisions;
3. accepted RFCs;
4. security and quality models;
5. project charter and protocol entry points;
6. nearest `AGENTS.md`;
7. governing issue and pull request;
8. latest applicable handoff;
9. session summaries;
10. temporary notes.

Sessions and handoffs preserve continuity and evidence. They cannot silently
change architecture, protocol, security boundaries or acceptance state.

## Repository map

Every top-level directory has exactly one current responsibility:

| Path | Responsibility |
| --- | --- |
| `.context/` | Durable engineering memory and decisions |
| `.github/` | GitHub automation, templates and repository presentation assets |
| `conformance/` | Executable protocol qualification corpus and independent runners |
| `internal/` | Private Go reference-relay implementation |
| `js/` | Independent JavaScript replay implementation and its tests |
| `schema/` | Public, machine-readable protocol contracts |

Root Markdown files are stable project entry points and policies. A new
top-level directory requires an accepted decision that states a distinct,
current responsibility. Archives, generated output, scratch work and duplicate
documentation are forbidden on `main`.

## Safety

This directory is public. Never store credentials, secrets, personal data,
sensitive infrastructure details, unrestricted transcripts or private
reasoning here.
