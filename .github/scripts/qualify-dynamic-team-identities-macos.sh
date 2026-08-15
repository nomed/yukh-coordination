#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly launcher="$root/.github/scripts/yukh-local-agent.py"
readonly required_revision="e28809b937f6897db5fbb9bf3eb39fe942134abe"
readonly scratch="$(mktemp -d "${TMPDIR:-/tmp}/yukh-dynamic-agents.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

git -C "$root" merge-base --is-ancestor "$required_revision" HEAD || {
  echo "dynamic-agents: FAIL checkout predates $required_revision" >&2
  exit 2
}

qualify() {
  local slot="$1"
  local agent="agent-team-probe-${slot}-$$"
  "$launcher" "$agent" session bootstrap >"$scratch/$slot.bootstrap"
  printf '%s\n' \
    "{\"capabilities\":[\"publish\",\"replay\"],\"session_label\":\"$agent\",\"status\":\"available\"}" |
    "$launcher" "$agent" session join >"$scratch/$slot.join"
  "$launcher" "$agent" events replay >"$scratch/$slot.replay"
}

pids=()
for slot in one two three four; do
  qualify "$slot" >"$scratch/$slot.log" 2>"$scratch/$slot.error" &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done
if [[ "$failed" != 0 ]]; then
  cat "$scratch"/*.error >&2
  echo "dynamic-agents: FAIL concurrent bootstrap/join/replay" >&2
  exit 1
fi

python3 - "$scratch" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
for path in sorted(root.glob("*.bootstrap")) + sorted(root.glob("*.join")) + sorted(root.glob("*.replay")):
    value = json.loads(path.read_text())
    if value.get("schema") != 1 or value.get("status") != "ok":
        raise SystemExit(f"dynamic-agents: FAIL {path.name}")
print("dynamic-agents: PASS identities=4 bootstrap=4 join=4 replay=4")
PY
