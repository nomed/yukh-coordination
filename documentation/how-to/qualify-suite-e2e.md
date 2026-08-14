# Qualify the private Yukh suite E2E demo

## Try it on a Mac

From a clean Coordination checkout, run:

```sh
.github/scripts/try-yukh-suite-macos.sh
```

The script installs missing Go, Node.js 24 and `nats-server` packages through
Homebrew, prepares the other three repositories under `~/yukh-preview-rc1`,
runs the four-component suite, then qualifies the macOS clients against a
test-owned local JetStream process. It leaves the JSON result in
`~/yukh-preview-rc1/yukh-suite-summary.json`; JetStream stops when the test
finishes.

This is the first runnable local preview qualification. It exercises the four
components and the real Coordination JetStream adapters with synthetic data.
It is not yet an interactive long-running coordinator.

Use the cross-suite runner to execute the four synthetic component
qualifications from one Coordination checkout:

```sh
.github/scripts/qualify-yukh-suite-e2e.sh
```

The runner is governed by
[`nomed/nomed.github.io#40`](https://github.com/nomed/nomed.github.io/issues/40)
and the accepted execution-forbidden Coordination boundary in RFC-0025. It is
private qualification evidence only. It does not release, publish, deploy,
contact GitHub or a provider, perform live mutations, or establish production
readiness.

## Prepare the checkouts once

Use these runtimes:

- Go 1.26 or later with the selected toolchain already installed;
- Node.js 24, including its matching `npm`, selected on `PATH`;
- Python 3; and
- Git.

Each JavaScript checkout must already contain dependencies installed from its
lockfile. Run `npm ci` once in that checkout when preparing it. The suite runner
never runs `npm install`, `npm ci`, an updater, or an audit. It sets npm to
offline mode, disables update checks and telemetry, sets `GOPROXY=off`, and
sets `GOTOOLCHAIN=local`; a missing dependency or toolchain therefore fails
preflight instead of reaching a public registry.

The Site preflight also resolves and loads the installed platform-specific
Next.js SWC native binding (`darwin-arm64`, `darwin-x64`, or the matching
glibc/musl Linux binding). This prevents Next.js from entering its binding
download fallback after execution starts. Native Windows is not supported by
this Bash runner.

Every checkout must be a clean Git worktree before execution and must remain
clean after its component command. Staged, unstaged, and non-ignored untracked
paths fail qualification. Generated paths are exempt only when the component
repository explicitly lists them in `.gitignore`; the commit SHA and clean-tree
state are recorded in the final summary.

Place the repositories as siblings:

```text
work/
├── nomed.github.io/
├── yukh-projects/
├── yukh-mcp/
└── yukh-coordination/
```

From `yukh-coordination`, the runner then discovers the other three checkouts.
For a worktree or another layout, provide paths explicitly:

```sh
SITE=/path/to/nomed.github.io \
PROJECTS=/path/to/yukh-projects \
MCP=/path/to/yukh-mcp \
.github/scripts/qualify-yukh-suite-e2e.sh
```

`COORDINATION` can select a different Coordination checkout.
`YUKH_REPOS_ROOT` can select a directory containing the other three sibling
repositories. Equivalent `--site`, `--projects`, `--mcp`, `--coordination`,
and `--repos-root` options are available; run the script with `--help` for the
complete interface.

## Execution and output

The runner validates every path, runtime, installed dependency directory, and
Git commit before executing these commands in fail-fast order:

1. Site: `npm run e2e`
2. Projects: `npm --silent run demo:e2e`
3. MCP: `npm run demo:e2e`
4. Coordination: `.github/scripts/qualify-coordination-e2e.sh`

Component output is streamed unchanged. On the first failure, no later
component starts. The final human-readable table records each component as
`PASS`, `FAIL`, or `NOT_RUN`, with its duration and commit. A successful run
ends with `Result: 4/4 PASS`.

The final `YUKH_E2E_SUMMARY_JSON=...` line contains the same evidence in a
machine-readable schema, including total duration, component paths, commits,
clean-tree evidence, commands, statuses, and durations. To also write the JSON
atomically to a file, set `YUKH_E2E_SUMMARY_PATH` or pass `--summary`:

```sh
YUKH_E2E_SUMMARY_PATH=/tmp/yukh-e2e-summary.json \
.github/scripts/qualify-yukh-suite-e2e.sh
```

When a summary file is requested, the atomic write completes before the runner
prints `PASS`. A write or rename error produces an overall `FAIL` and a matching
failure JSON line on standard output.

Run the targeted fail-closed runner tests with:

```sh
.github/scripts/test-qualify-yukh-suite-e2e.sh
```

They cover an absent SWC binding, a dirty component worktree, and requested
summary persistence failure without contacting a registry or service.

The component suites own their test processes, loopback listeners, ephemeral
ports, fixtures, and cleanup. The runner does not launch background services.
A successful `4/4 PASS` means each suite completed its cleanup contract; it
does not authorize external networking, credentials, a deployed environment,
or any public dependency.
