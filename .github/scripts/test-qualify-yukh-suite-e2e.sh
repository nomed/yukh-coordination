#!/usr/bin/env bash
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly runner="$repository_root/.github/scripts/qualify-yukh-suite-e2e.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/yukh-suite-runner-test.XXXXXXXXXX")"

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

swc_package="$(
  node - <<'NODE'
const { arch, platform, report } = process;
if (platform === "darwin" && (arch === "arm64" || arch === "x64")) {
  process.stdout.write(`@next/swc-darwin-${arch}`);
} else if (platform === "linux" && (arch === "arm64" || arch === "x64")) {
  const header = report?.getReport()?.header ?? {};
  process.stdout.write(`@next/swc-linux-${arch}-${header.glibcVersionRuntime ? "gnu" : "musl"}`);
} else {
  process.exit(1);
}
NODE
)"

create_repository() {
  local path="$1"
  mkdir -p "$path"
  git -C "$path" init -q
  git -C "$path" config user.name "Yukh runner test"
  git -C "$path" config user.email "runner-test@example.invalid"
}

commit_repository() {
  local path="$1"
  git -C "$path" add -f .
  git -C "$path" commit -qm "Create runner fixture"
}

create_suite() {
  local root="$1"
  local include_swc="$2"
  local repository

  mkdir -p "$root"
  for repository in site projects mcp coordination; do
    create_repository "$root/$repository"
  done

  cat >"$root/site/package.json" <<'JSON'
{"private":true,"scripts":{"e2e":"node -e \"process.stdout.write('site fixture: PASS\\\\n')\""}}
JSON
  cat >"$root/projects/package.json" <<'JSON'
{"private":true,"scripts":{"demo:e2e":"node -e \"process.stdout.write('projects fixture: PASS\\\\n')\""}}
JSON
  cat >"$root/mcp/package.json" <<'JSON'
{"private":true,"scripts":{"demo:e2e":"node -e \"process.stdout.write('mcp fixture: PASS\\\\n')\""}}
JSON

  mkdir -p \
    "$root/site/node_modules/.bin" \
    "$root/projects/node_modules/.bin" \
    "$root/mcp/node_modules/.bin" \
    "$root/coordination/.github/scripts"
  printf '#!/usr/bin/env sh\nexit 0\n' >"$root/site/node_modules/.bin/next"
  printf '#!/usr/bin/env sh\nexit 0\n' >"$root/projects/node_modules/.bin/tsc"
  printf '#!/usr/bin/env sh\nexit 0\n' >"$root/mcp/node_modules/.bin/tsx"
  printf '#!/usr/bin/env sh\necho "coordination fixture: PASS"\n' \
    >"$root/coordination/.github/scripts/qualify-coordination-e2e.sh"
  chmod +x \
    "$root/site/node_modules/.bin/next" \
    "$root/projects/node_modules/.bin/tsc" \
    "$root/mcp/node_modules/.bin/tsx" \
    "$root/coordination/.github/scripts/qualify-coordination-e2e.sh"

  if [[ "$include_swc" == "yes" ]]; then
    mkdir -p "$root/site/node_modules/$swc_package"
    cat >"$root/site/node_modules/$swc_package/package.json" <<'JSON'
{"main":"index.js"}
JSON
    printf 'module.exports = {};\n' >"$root/site/node_modules/$swc_package/index.js"
  fi

  printf '.next/\ndist/\n' >"$root/site/.gitignore"

  for repository in site projects mcp coordination; do
    commit_repository "$root/$repository"
  done

  mkdir -p "$root/site/.next"
  printf 'ignored generated output\n' >"$root/site/.next/generated"
}

run_fixture() {
  local root="$1"
  shift
  SITE="$root/site" \
    PROJECTS="$root/projects" \
    MCP="$root/mcp" \
    COORDINATION="$root/coordination" \
    "$runner" "$@"
}

missing_swc="$work/missing-swc"
create_suite "$missing_swc" no
if run_fixture "$missing_swc" >"$work/missing-swc.out" 2>&1; then
  echo "missing SWC binding unexpectedly passed" >&2
  exit 1
fi
grep -Fq "requires installed native binding $swc_package" "$work/missing-swc.out"
grep -Fq '"status":"FAIL"' "$work/missing-swc.out"
if grep -Fq "==> [1/4]" "$work/missing-swc.out"; then
  echo "a component started before SWC preflight completed" >&2
  exit 1
fi

dirty="$work/dirty"
create_suite "$dirty" yes
printf 'relevant untracked input\n' >"$dirty/projects/untracked.txt"
if run_fixture "$dirty" >"$work/dirty.out" 2>&1; then
  echo "dirty worktree unexpectedly passed" >&2
  exit 1
fi
grep -Fq "Projects checkout is dirty" "$work/dirty.out"
grep -Fq '"worktree":"DIRTY"' "$work/dirty.out"
if grep -Fq "==> [1/4]" "$work/dirty.out"; then
  echo "a component started before clean-tree preflight completed" >&2
  exit 1
fi

summary_failure="$work/summary-failure"
create_suite "$summary_failure" yes
mkdir "$work/summary-target"
if run_fixture "$summary_failure" --summary "$work/summary-target" \
  >"$work/summary-failure.out" 2>&1; then
  echo "summary persistence failure unexpectedly passed" >&2
  exit 1
fi
grep -Fq "summary persistence failed" "$work/summary-failure.out"
grep -Fq "Result: 4/4 FAIL" "$work/summary-failure.out"
grep -Fq '"status":"FAIL"' "$work/summary-failure.out"
if grep -Fq "Result: 4/4 PASS" "$work/summary-failure.out"; then
  echo "PASS was emitted before summary persistence succeeded" >&2
  exit 1
fi

echo "suite-runner-tests: PASS missing-swc dirty-worktree summary-persistence"
