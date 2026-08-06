#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
readonly repository_root
readonly canonical="$repository_root/.github/records/private-primitives-oci-review-candidate.txt"
work="$(mktemp -d "${repository_root}/.qualification-test-primitives-oci-record.XXXXXXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

"$repository_root/.github/scripts/compare-primitives-oci-record.sh" \
  "$canonical" "$canonical" >/dev/null

cp "$canonical" "$work/digest-mismatch.txt"
sed -i.bak \
  's/manifest=sha256:aed277/manifest=sha256:bed277/' \
  "$work/digest-mismatch.txt"
rm "$work/digest-mismatch.txt.bak"
if "$repository_root/.github/scripts/compare-primitives-oci-record.sh" \
  "$canonical" "$work/digest-mismatch.txt" >"$work/mismatch.out" 2>&1; then
  echo "Digest mismatch test unexpectedly passed" >&2
  exit 1
fi
grep -q 'does not match exact-source qualification' "$work/mismatch.out"

cp "$canonical" "$work/stale-source.txt"
sed -i.bak \
  's/source=92678da9d1d866c50371a683845c4675bf45c055/source=ee8d74d89fdc30f37d4d8e8c75c922a473c6d9c6/' \
  "$work/stale-source.txt"
rm "$work/stale-source.txt.bak"
if "$repository_root/.github/scripts/verify-recorded-primitives-oci.sh" \
  "$work/stale-source.txt" >"$work/stale.out" 2>&1; then
  echo "Stale source test unexpectedly passed" >&2
  exit 1
fi
grep -q 'source commit/tree binding is stale or mismatched' "$work/stale.out"

printf 'digest_mismatch_failure=verified\nstale_source_failure=verified\n'
