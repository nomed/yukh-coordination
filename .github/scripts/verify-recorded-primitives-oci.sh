#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
readonly repository_root
readonly record="${1:-$repository_root/.github/records/private-primitives-oci-review-candidate.txt}"

read_field() {
  local key="$1"
  local value
  value="$(awk -F= -v key="$key" '$1 == key {print $2}' "$record")"
  if [[ -z "$value" ]] || [[ "$(grep -c "^${key}=" "$record")" != 1 ]]; then
    echo "Recorded OCI review candidate has invalid $key" >&2
    exit 1
  fi
  printf '%s\n' "$value"
}

source_commit="$(read_field source)"
source_tree="$(read_field source_tree)"
readonly source_commit source_tree
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]] ||
  [[ ! "$source_tree" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Recorded OCI source identity is not exact" >&2
  exit 1
fi

actual_tree="$(git rev-parse --verify "${source_commit}^{tree}" 2>/dev/null || true)"
if [[ "$actual_tree" != "$source_tree" ]]; then
  echo "Recorded OCI source commit/tree binding is stale or mismatched" >&2
  exit 1
fi

result="$(mktemp "${repository_root}/.qualification-recorded-primitives-oci.XXXXXXXXXX")"
cleanup() {
  rm -f -- "$result"
}
trap cleanup EXIT

"$repository_root/.github/scripts/qualify-primitives-oci.sh" \
  "$source_commit" >"$result"
"$repository_root/.github/scripts/compare-primitives-oci-record.sh" \
  "$record" "$result"
printf 'recorded_source=%s\nrecorded_source_tree=%s\n' \
  "$source_commit" "$source_tree"
