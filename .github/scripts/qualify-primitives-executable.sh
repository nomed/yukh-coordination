#!/usr/bin/env bash
set -euo pipefail

first="$(mktemp)"
second="$(mktemp)"
trap 'rm -f -- "$first" "$second"' EXIT

package="./internal/primitivesstaging/cmd/yukh-coordination-primitives"
revision="$(git rev-parse HEAD)"
embedded="yukh-coordination-revision:$revision"
ldflags="-buildid= -X main.buildRevision=$embedded"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$first" "$package"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$second" "$package"
cmp -- "$first" "$second"

contents="$(strings "$first")"
case "$contents" in
  *"$embedded"*) ;;
  *) exit 1 ;;
esac
