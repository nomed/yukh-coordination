#!/usr/bin/env bash
set -euo pipefail

readonly expected="${1:?usage: compare-primitives-oci-record.sh EXPECTED ACTUAL}"
readonly actual="${2:?usage: compare-primitives-oci-record.sh EXPECTED ACTUAL}"

for record in "$expected" "$actual"; do
  if [[ ! -f "$record" ]]; then
    echo "OCI candidate record is missing: $record" >&2
    exit 1
  fi
  if grep -Evq \
    '^[a-z_]+=(sha256:)?[a-z0-9.-]+$' "$record"; then
    echo "OCI candidate record has an invalid field" >&2
    exit 1
  fi
  if [[ "$(cut -d= -f1 "$record" | sort | uniq -d | wc -l | tr -d ' ')" != 0 ]]; then
    echo "OCI candidate record has a duplicate field" >&2
    exit 1
  fi
done

if ! diff -u "$expected" "$actual"; then
  echo "Recorded OCI review candidate does not match exact-source qualification" >&2
  exit 1
fi

printf 'recorded_candidate=verified\n'
