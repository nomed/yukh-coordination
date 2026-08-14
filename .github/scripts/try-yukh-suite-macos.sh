#!/usr/bin/env bash
set -euo pipefail

readonly coordination_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly target_root="${YUKH_PREVIEW_HOME:-$HOME/yukh-preview-rc1}"
readonly site_revision="7d17d63d41b676949682b87eb5ceb6aee137ce49"
readonly projects_revision="9b0a4e252e179e24d70b308e3f0b8853e78881c0"
readonly mcp_revision="dbec60834148ea8086582e1c60bbf3c19c14eb00"

fail() { echo "yukh-macos: $*" >&2; exit 2; }
test "$(uname -s)" = Darwin || fail "macOS is required"
command -v git >/dev/null || fail "git is required"
command -v brew >/dev/null || fail "Homebrew is required: https://brew.sh"

packages=()
command -v go >/dev/null || packages+=(go)
command -v nats-server >/dev/null || packages+=(nats-server)
if ! command -v node >/dev/null || [[ "$(node -p 'process.versions.node.split(`.`)[0]' 2>/dev/null || true)" != 24 ]]; then
  packages+=(node@24)
fi
if ((${#packages[@]})); then
  echo "Installing: ${packages[*]}"
  brew install "${packages[@]}"
fi

node_prefix="$(brew --prefix node@24 2>/dev/null || true)"
if [[ -n "$node_prefix" ]]; then
  export PATH="$node_prefix/bin:$PATH"
fi
case "$(go env GOVERSION)" in go1.26*) ;; *) fail "Go 1.26 is required; found $(go env GOVERSION)";; esac
[[ "$(node -p 'process.versions.node.split(`.`)[0]')" = 24 ]] || fail "Node.js 24 is required"
command -v nats-server >/dev/null || fail "nats-server is unavailable after installation"

mkdir -p "$target_root"

prepare_repo() {
  local name="$1" revision="$2" path="$target_root/$1"
  if [[ ! -d "$path/.git" ]]; then
    git clone --filter=blob:none "https://github.com/nomed/$name.git" "$path"
  fi
  [[ -z "$(git -C "$path" status --porcelain)" ]] || fail "$path has local changes"
  git -C "$path" fetch --depth=1 origin "$revision"
  git -C "$path" checkout --detach "$revision"
}

prepare_repo nomed.github.io "$site_revision"
prepare_repo yukh-projects "$projects_revision"
prepare_repo yukh-mcp "$mcp_revision"

for repository in nomed.github.io yukh-projects yukh-mcp; do
  echo "Installing locked dependencies: $repository"
  (cd "$target_root/$repository" && npm ci --no-audit --no-fund)
done

# The suite runner deliberately disables module lookup. Populate and verify the
# selected Go module cache while network access is still allowed.
echo "Installing locked dependencies: yukh-coordination"
(cd "$coordination_root" && go mod download && go mod verify)

summary="$target_root/yukh-suite-summary.json"
echo "Running the four-component suite"
SITE="$target_root/nomed.github.io" \
PROJECTS="$target_root/yukh-projects" \
MCP="$target_root/yukh-mcp" \
COORDINATION="$coordination_root" \
YUKH_E2E_SUMMARY_PATH="$summary" \
  "$coordination_root/.github/scripts/qualify-yukh-suite-e2e.sh"

echo "Running local NATS JetStream and macOS client qualification"
"$coordination_root/.github/scripts/qualify-macos-local.sh"

printf '\nyukh-macos: PASS\nsummary: %s\nJetStream: local test-owned nats-server process; stopped after qualification\n' "$summary"
