# Workstation bootstrap reconciliation

## Sources

- Authoritative base: `origin/main` at `83626eb`
- Preserved owner WIP: `wip/workstation-bootstrap-local` at `1aead79`
- Reconciliation branch: `agent/workstation-bootstrap-reconcile`

The owner WIP remains unchanged on GitHub.

## Retention decisions

| WIP content | Reconciled content | Reason |
| --- | --- | --- |
| RFC-0025 through RFC-0028 | RFC-0026 through RFC-0029 | RFC-0025 is already the authoritative first-preview profile; only identifiers and internal references change. |
| `clientcli/bootstrap.go` workstation runner | `clientcli/workstation_bootstrap.go` | Preserve the complete workstation CLI contract without replacing the newer descriptor-based bootstrap runner on `main`. |
| WIP command routing | executable `application` routing in `cmd/yukh-coordination` | Preserve both the released executable syntax and the explicit workstation syntax; neither silently falls back to the other. |
| WIP HTTPS issuer | existing `clientauth.HTTPIssuer` | The main issuer is the same port with stricter canonical-body, UUIDv7, lifetime, redirect and size verification. Both workstation factories use it. Keeping the weaker duplicate would create divergent security behavior. |
| Keychain, macOS, Secret Service, token-FD and workstation packages/tests | retained | No replacement exists on `main`; all source and tests are carried forward. |
| Linux GNOME Keyring/KeePassXC qualification scripts | retained | They remain the platform-specific qualification boundary. |

No behavior or test is discarded without the superseding mapping above. Native
macOS Keychain execution and the Docker-owned GNOME Keyring test still require
their respective hosts; cross-build and hermetic Go tests do not replace them.
