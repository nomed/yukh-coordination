#!/usr/bin/env bash
set -euo pipefail

candidate="${1:-$(git rev-parse HEAD)}"
candidate="$(git rev-parse --verify "${candidate}^{commit}")"
if [[ ! "$candidate" =~ ^[0-9a-f]{40}$ ]]; then
  echo "OCI qualification requires an exact source commit" >&2
  exit 1
fi
candidate_tree="$(git rev-parse --verify "${candidate}^{tree}")"

repository_root="$(git rev-parse --show-toplevel)"
work="$(mktemp -d "${repository_root}/.qualification-primitives-oci.XXXXXXXXXX")"
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
first_source="$work/source-first"
second_source="$work/source-second"
first="$work/oci-first"
second="$work/oci-second"
mkdir "$first_source" "$second_source"
git archive "$candidate" | tar --no-same-owner -x -C "$first_source"
git archive "$candidate" | tar --no-same-owner -x -C "$second_source"

"$repository_root/.github/scripts/build-primitives-oci.sh" \
  "$first" "$first_source" "$candidate"
"$repository_root/.github/scripts/build-primitives-oci.sh" \
  "$second" "$second_source" "$candidate"
diff -ru --no-dereference "$first" "$second"

manifest_digest="$(awk -F= '$1 == "manifest" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
config_digest="$(awk -F= '$1 == "config" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
layer_digest="$(awk -F= '$1 == "layer" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
sbom_digest="$(awk -F= '$1 == "sbom" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
service_digest="$(awk -F= '$1 == "service" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
bootstrap_digest="$(awk -F= '$1 == "bootstrap" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
launcher_digest="$(awk -F= '$1 == "launcher" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"

sha256sum --check --status <<EOF
$manifest_digest  $first/blobs/sha256/$manifest_digest
$config_digest  $first/blobs/sha256/$config_digest
$layer_digest  $first/blobs/sha256/$layer_digest
$sbom_digest  $first/sbom.spdx.json
EOF
grep -q '"User":"65532:65532"' "$first/blobs/sha256/$config_digest"
grep -q '"Entrypoint":\["/usr/local/bin/yukh-coordination-secret-launcher"\]' \
  "$first/blobs/sha256/$config_digest"
test "$(tar -xOf "$first/blobs/sha256/$layer_digest" \
  ./usr/local/bin/yukh-coordination-primitives | sha256sum | cut -d' ' -f1)" = "$service_digest"
test "$(tar -xOf "$first/blobs/sha256/$layer_digest" \
  ./usr/local/bin/yukh-coordination-primitives-bootstrap | sha256sum | cut -d' ' -f1)" = "$bootstrap_digest"
test "$(tar -xOf "$first/blobs/sha256/$layer_digest" \
  ./usr/local/bin/yukh-coordination-secret-launcher | sha256sum | cut -d' ' -f1)" = "$launcher_digest"

mapfile -t paths < <(tar -tf "$first/blobs/sha256/$layer_digest" | sort)
readonly expected=(
  ./
  ./etc/
  ./etc/group
  ./etc/passwd
  ./usr/
  ./usr/local/
  ./usr/local/bin/
  ./usr/local/bin/yukh-coordination-primitives
  ./usr/local/bin/yukh-coordination-primitives-bootstrap
  ./usr/local/bin/yukh-coordination-secret-launcher
  ./var/
  ./var/empty/
)
diff -u <(printf '%s\n' "${expected[@]}") <(printf '%s\n' "${paths[@]}")

if tar -tf "$first/blobs/sha256/$layer_digest" |
  grep -Eq '(^|/)(sh|bash|busybox|apk|apt|dpkg|rpm|curl|wget)$'; then
  echo "Forbidden executable in OCI layer" >&2
  exit 1
fi

evidence="$(cat "$first/digests.txt")"
cleanup
trap - EXIT
test ! -e "$work"
printf 'record_format=private-primitives-oci-review-candidate-v1\n'
printf 'source_tree=%s\n' "$candidate_tree"
printf '%s\n' "$evidence"
printf 'builds=2\nbyte_identity=verified\n'
printf 'executable_allowlist=verified\ncleanup=verified\n'
