#!/usr/bin/env bash
set -uo pipefail

readonly runner_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

site_path="${SITE:-}"
projects_path="${PROJECTS:-}"
mcp_path="${MCP:-}"
coordination_path="${COORDINATION:-$runner_root}"
repos_root="${YUKH_REPOS_ROOT:-}"
summary_path="${YUKH_E2E_SUMMARY_PATH:-}"

usage() {
  cat <<'EOF'
Usage: .github/scripts/qualify-yukh-suite-e2e.sh [options]

Run the four private, synthetic Yukh E2E qualifications in fail-fast order.

Options:
  --site PATH          nomed.github.io checkout (env: SITE)
  --projects PATH      yukh-projects checkout (env: PROJECTS)
  --mcp PATH           yukh-mcp checkout (env: MCP)
  --coordination PATH  yukh-coordination checkout (env: COORDINATION)
  --repos-root PATH    parent of sibling repositories (env: YUKH_REPOS_ROOT)
  --summary PATH       additionally write the JSON summary (env: YUKH_E2E_SUMMARY_PATH)
  -h, --help           show this help

Without component overrides, repositories are resolved as siblings beneath
YUKH_REPOS_ROOT or the parent of the Coordination checkout.
EOF
}

while (($# > 0)); do
  case "$1" in
    --site|--projects|--mcp|--coordination|--repos-root|--summary)
      if (($# < 2)); then
        echo "missing value for $1" >&2
        exit 2
      fi
      case "$1" in
        --site) site_path="$2" ;;
        --projects) projects_path="$2" ;;
        --mcp) mcp_path="$2" ;;
        --coordination) coordination_path="$2" ;;
        --repos-root) repos_root="$2" ;;
        --summary) summary_path="$2" ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

canonical_directory() {
  if [[ ! -d "$1" ]]; then
    return 1
  fi
  (cd "$1" && pwd -P)
}

coordination_path="$(canonical_directory "$coordination_path")" || {
  echo "Coordination checkout does not exist: $coordination_path" >&2
  exit 2
}

if [[ -n "$repos_root" ]]; then
  repos_root="$(canonical_directory "$repos_root")" || {
    echo "repository root does not exist: $repos_root" >&2
    exit 2
  }
else
  repos_root="$(dirname "$coordination_path")"
fi

site_path="${site_path:-$repos_root/nomed.github.io}"
projects_path="${projects_path:-$repos_root/yukh-projects}"
mcp_path="${mcp_path:-$repos_root/yukh-mcp}"

readonly component_count=4
component_names=("Site" "Projects" "MCP" "Coordination")
component_paths=("$site_path" "$projects_path" "$mcp_path" "$coordination_path")
component_commands=(
  "npm run e2e"
  "npm --silent run demo:e2e"
  "npm run demo:e2e"
  ".github/scripts/qualify-coordination-e2e.sh"
)
component_statuses=("NOT_RUN" "NOT_RUN" "NOT_RUN" "NOT_RUN")
component_durations_ms=(0 0 0 0)
component_commits=("" "" "" "")

total_started_ms="$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)' 2>/dev/null || echo 0)"
current_component=-1
current_started_ms=0
failure_detail=""
summary_emitted=0

now_ms() {
  python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
}

emit_summary() {
  local exit_code="$1"
  local finished_ms total_duration_ms index

  if ((summary_emitted)); then
    return 0
  fi
  summary_emitted=1

  finished_ms="$(now_ms 2>/dev/null || echo "$total_started_ms")"
  total_duration_ms=$((finished_ms - total_started_ms))
  if ((current_component >= 0)) && [[ "${component_statuses[$current_component]}" == "RUNNING" ]]; then
    component_statuses[$current_component]="FAIL"
    component_durations_ms[$current_component]=$((finished_ms - current_started_ms))
  fi

  args=("$exit_code" "$total_duration_ms" "$failure_detail" "$summary_path")
  for ((index = 0; index < component_count; index++)); do
    args+=(
      "${component_names[$index]}"
      "${component_paths[$index]}"
      "${component_commands[$index]}"
      "${component_statuses[$index]}"
      "${component_durations_ms[$index]}"
      "${component_commits[$index]}"
    )
  done

  python3 - "${args[@]}" <<'PY'
import json
import os
import sys

exit_code = int(sys.argv[1])
total_duration_ms = int(sys.argv[2])
failure_detail = sys.argv[3]
summary_path = sys.argv[4]
fields = sys.argv[5:]
components = []
for offset in range(0, len(fields), 6):
    name, path, command, status, duration_ms, commit = fields[offset : offset + 6]
    components.append(
        {
            "name": name,
            "path": path,
            "commit": commit or None,
            "command": command,
            "status": status,
            "duration_ms": int(duration_ms),
        }
    )

passed = sum(component["status"] == "PASS" for component in components)
summary = {
    "schema_version": 1,
    "suite": "yukh-private-e2e",
    "status": "PASS" if exit_code == 0 and passed == len(components) else "FAIL",
    "passed": passed,
    "total": len(components),
    "duration_ms": total_duration_ms,
    "failure": failure_detail or None,
    "components": components,
}

print()
print("Yukh private E2E summary")
print(f"{'Component':<14} {'Status':<9} {'Duration':>10}  Commit")
for component in components:
    commit = component["commit"][:12] if component["commit"] else "-"
    duration = component["duration_ms"] / 1000
    print(f"{component['name']:<14} {component['status']:<9} {duration:>9.3f}s  {commit}")
print(
    f"Result: {passed}/{len(components)} "
    f"{'PASS' if summary['status'] == 'PASS' else 'FAIL'} "
    f"in {total_duration_ms / 1000:.3f}s"
)
if failure_detail:
    print(f"Failure: {failure_detail}", file=sys.stderr)

encoded = json.dumps(summary, separators=(",", ":"), sort_keys=True)
print(f"YUKH_E2E_SUMMARY_JSON={encoded}")

if summary_path:
    parent = os.path.dirname(os.path.abspath(summary_path))
    if not os.path.isdir(parent):
        raise SystemExit(f"summary parent directory does not exist: {parent}")
    temporary = f"{summary_path}.tmp.{os.getpid()}"
    with open(temporary, "w", encoding="utf-8") as handle:
        handle.write(encoded)
        handle.write("\n")
    os.replace(temporary, summary_path)
PY
}

fail() {
  local message="$1"
  failure_detail="$message"
  echo "preflight: FAIL: $message" >&2
  emit_summary 2
  exit 2
}

handle_signal() {
  failure_detail="interrupted by signal $1"
  echo "$failure_detail" >&2
  emit_summary 130
  exit 130
}

trap 'handle_signal HUP' HUP
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM

for ((index = 0; index < component_count; index++)); do
  component_paths[$index]="$(canonical_directory "${component_paths[$index]}")" ||
    fail "${component_names[$index]} checkout does not exist: ${component_paths[$index]}"
done

command -v go >/dev/null 2>&1 || fail "Go 1.26 is required"
command -v node >/dev/null 2>&1 || fail "Node.js 24 is required"
command -v npm >/dev/null 2>&1 || fail "npm for Node.js 24 is required"
command -v python3 >/dev/null 2>&1 || fail "Python 3 is required"
command -v git >/dev/null 2>&1 || fail "git is required to bind checkout commits"

go_version="$(go env GOVERSION 2>/dev/null)" || fail "could not read the Go version"
go_minor="$(printf '%s\n' "$go_version" | sed -nE 's/^go1\.([0-9]+)(\..*)?$/\1/p')"
[[ -n "$go_minor" ]] || fail "could not parse Go version: $go_version"
((go_minor >= 26)) || fail "Go 1.26 or later is required; found $go_version"

node_version="$(node --version 2>/dev/null)" || fail "could not read the Node.js version"
node_major="$(printf '%s\n' "$node_version" | sed -nE 's/^v([0-9]+)\..*$/\1/p')"
[[ "$node_major" == "24" ]] ||
  fail "Node.js 24 is required; found $node_version (select Node 24 on PATH)"

python_version="$(python3 -c 'import sys; print(sys.version_info.major)' 2>/dev/null)" ||
  fail "could not read the Python version"
[[ "$python_version" == "3" ]] || fail "Python 3 is required"

for index in 0 1 2; do
  [[ -f "${component_paths[$index]}/package.json" ]] ||
    fail "${component_names[$index]} is missing package.json: ${component_paths[$index]}"
  [[ -d "${component_paths[$index]}/node_modules" ]] ||
    fail "${component_names[$index]} dependencies are absent; run npm ci once in ${component_paths[$index]}"
done

[[ -x "${component_paths[0]}/node_modules/.bin/next" ]] ||
  fail "Site dependencies are incomplete; run npm ci once in ${component_paths[0]}"
[[ -x "${component_paths[1]}/node_modules/.bin/tsc" ]] ||
  fail "Projects dependencies are incomplete; run npm ci once in ${component_paths[1]}"
[[ -x "${component_paths[2]}/node_modules/.bin/tsx" ]] ||
  fail "MCP dependencies are incomplete; run npm ci once in ${component_paths[2]}"
[[ -x "${component_paths[3]}/.github/scripts/qualify-coordination-e2e.sh" ]] ||
  fail "Coordination qualification script is absent or not executable: ${component_paths[3]}"

for ((index = 0; index < component_count; index++)); do
  component_commits[$index]="$(git -C "${component_paths[$index]}" rev-parse HEAD 2>/dev/null)" ||
    fail "${component_names[$index]} checkout is not a Git worktree"
done

# Commands may use only installed dependencies and local test-owned resources.
export GOTOOLCHAIN=local
export GOPROXY=off
export NEXT_TELEMETRY_DISABLED=1
export npm_config_audit=false
export npm_config_fund=false
export npm_config_offline=true
export npm_config_update_notifier=false

run_component() {
  local index="$1"
  local status
  current_component="$index"
  current_started_ms="$(now_ms)"
  component_statuses[$index]="RUNNING"

  printf '\n==> [%d/%d] %s\n' "$((index + 1))" "$component_count" "${component_names[$index]}"
  printf '    path: %s\n' "${component_paths[$index]}"
  printf '    commit: %s\n' "${component_commits[$index]}"
  printf '    command: %s\n\n' "${component_commands[$index]}"

  case "$index" in
    0) (cd "${component_paths[$index]}" && npm run e2e) ;;
    1) (cd "${component_paths[$index]}" && npm --silent run demo:e2e) ;;
    2) (cd "${component_paths[$index]}" && npm run demo:e2e) ;;
    3) (cd "${component_paths[$index]}" && .github/scripts/qualify-coordination-e2e.sh) ;;
  esac
  status=$?

  component_durations_ms[$index]=$(($(now_ms) - current_started_ms))
  current_component=-1
  if ((status == 0)); then
    component_statuses[$index]="PASS"
    printf '\n<== %s: PASS (%.3fs)\n' \
      "${component_names[$index]}" \
      "$(python3 -c "print(${component_durations_ms[$index]} / 1000)")"
    return 0
  fi

  component_statuses[$index]="FAIL"
  failure_detail="${component_names[$index]} exited with status $status"
  printf '\n<== %s: FAIL (status=%d, %.3fs)\n' \
    "${component_names[$index]}" \
    "$status" \
    "$(python3 -c "print(${component_durations_ms[$index]} / 1000)")" >&2
  return "$status"
}

for ((index = 0; index < component_count; index++)); do
  run_component "$index"
  status=$?
  if ((status != 0)); then
    emit_summary "$status"
    exit "$status"
  fi
done

emit_summary 0 || exit 2
