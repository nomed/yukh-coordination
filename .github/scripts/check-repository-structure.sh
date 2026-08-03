#!/usr/bin/env bash
set -euo pipefail

readonly allowed_directories=(.context .github conformance internal js schema)
readonly required_context=(
  .context/README.md
  .context/current.md
  .context/manifest.yaml
  .context/decisions
  .context/rfcs
  .context/security
  .context/sessions
  .context/templates
)

mapfile -t actual_directories < <(
  find . -mindepth 1 -maxdepth 1 -type d ! -name .git -printf '%f\n' | sort
)
mapfile -t expected_directories < <(printf '%s\n' "${allowed_directories[@]}" | sort)

if ! diff -u <(printf '%s\n' "${expected_directories[@]}") <(printf '%s\n' "${actual_directories[@]}"); then
  echo "Top-level directory map differs from .context/README.md" >&2
  exit 1
fi

for path in "${required_context[@]}"; do
  if [[ ! -e "$path" ]]; then
    echo "Missing required context path: $path" >&2
    exit 1
  fi
done

if [[ -e docs || -e test ]]; then
  echo "Legacy compatibility trees docs/ and test/ are forbidden" >&2
  exit 1
fi
