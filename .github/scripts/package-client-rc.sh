#!/usr/bin/env bash
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
revision="$(git rev-parse HEAD)"
version="${1:-0.1.0-rc.1}"
output="${2:-$root/dist}"
case "$version" in *[!0-9A-Za-z.-]*|'') echo "invalid version" >&2; exit 2;; esac
case "$output" in /*) ;; *) echo "output must be absolute" >&2; exit 2;; esac
mkdir -p "$output"
work="$(mktemp -d "$root/.package-client-rc.XXXXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
for architecture in amd64 arm64; do
  name="yukh-coordination_${version}_linux_${architecture}"
  first="$work/$name.first"; second="$work/$name.second"
  flags="-buildid= -X github.com/nomed/yukh-coordination/internal/clientcli.Version=$version"
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$first" ./internal/clientcli/cmd/yukh-coordination
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -buildvcs=false -ldflags "$flags" -o "$second" ./internal/clientcli/cmd/yukh-coordination
  cmp -- "$first" "$second"
  strings "$first" > "$work/$name.strings"
  grep -Fq -- "$version" "$work/$name.strings"
  install -m 0755 "$first" "$output/$name"
done
printf 'version=%s\nrevision=%s\n' "$version" "$revision" > "$output/BUILD-INFO-$version"
(cd "$output" && sha256sum "yukh-coordination_${version}_linux_amd64" "yukh-coordination_${version}_linux_arm64" > "SHA256SUMS-$version")
printf 'client-package: PASS version=%s revision=%s output=%s\n' "$version" "$revision" "$output"
