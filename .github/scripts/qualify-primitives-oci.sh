#!/usr/bin/env bash
set -euo pipefail

first="$(mktemp -d)"
second="$(mktemp -d)"
trap 'rm -rf -- "$first" "$second"' EXIT
rmdir "$first" "$second"

.github/scripts/build-primitives-oci.sh "$first"
.github/scripts/build-primitives-oci.sh "$second"
diff -ru --no-dereference "$first" "$second"

manifest_digest="$(awk -F= '$1 == "manifest" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
config_digest="$(awk -F= '$1 == "config" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
layer_digest="$(awk -F= '$1 == "layer" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
sbom_digest="$(awk -F= '$1 == "sbom" {sub(/^sha256:/, "", $2); print $2}' "$first/digests.txt")"
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

cat "$first/digests.txt"
