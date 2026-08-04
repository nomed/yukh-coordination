#!/usr/bin/env bash
set -euo pipefail

first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f -- "$first" "$second"' EXIT
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-buildid=" \
  -o "$first" ./internal/primitivesceremony/cmd/yukh-coordination-offline-ceremony
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-buildid=" \
  -o "$second" ./internal/primitivesceremony/cmd/yukh-coordination-offline-ceremony
cmp -- "$first" "$second"
contents="$(strings "$first")"
case "$contents" in
  *yukh-coordination/private-primitives-offline-ceremony-v1*) ;;
  *) exit 1 ;;
esac
sha256sum "$first" | sed 's#  .*#  yukh-coordination-offline-ceremony#'
