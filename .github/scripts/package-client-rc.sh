#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
revision="$(git -C "$root" rev-parse HEAD)"
version="${1:-0.1.0-rc.2}"
output="${2:-$root/dist}"
case "$version" in *[!0-9A-Za-z.-]*|'') echo "invalid version" >&2; exit 2;; esac
case "$output" in /*) ;; *) echo "output must be absolute" >&2; exit 2;; esac
mkdir -p "$output"
cd "$root"
work="$(mktemp -d "$root/.package-client-rc.XXXXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
artifacts=()
for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  operating_system="${platform%/*}"
  architecture="${platform#*/}"
  name="yukh-coordination_${version}_${operating_system}_${architecture}"
  first="$work/$name.first"; second="$work/$name.second"
  flags="-buildid= -X github.com/nomed/yukh-coordination/internal/clientcli.Version=$version"
  CGO_ENABLED=0 GOOS="$operating_system" GOARCH="$architecture" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$first" ./internal/clientcli/cmd/yukh-coordination
  CGO_ENABLED=0 GOOS="$operating_system" GOARCH="$architecture" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$second" ./internal/clientcli/cmd/yukh-coordination
  cmp -- "$first" "$second"
  strings "$first" > "$work/$name.strings"
  grep -Fq -- "$version" "$work/$name.strings"
  install -m 0755 "$first" "$output/$name"
  artifacts+=("$name")
done
printf 'version=%s\nrevision=%s\n' "$version" "$revision" > "$output/BUILD-INFO-$version"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output" && sha256sum "${artifacts[@]}" > "SHA256SUMS-$version")
else
  (cd "$output" && shasum -a 256 "${artifacts[@]}" > "SHA256SUMS-$version")
fi
printf 'client-package: PASS version=%s revision=%s output=%s\n' "$version" "$revision" "$output"
