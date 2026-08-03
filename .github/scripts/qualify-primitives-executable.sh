#!/usr/bin/env bash
set -euo pipefail

revision="$(git rev-parse HEAD)"

qualify() {
  local package="$1"
  local ldflags="$2"
  local marker="$3"
  local first second contents
  first="$(mktemp)"
  second="$(mktemp)"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$first" "$package"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$second" "$package"
  cmp -- "$first" "$second"
  contents="$(strings "$first")"
  case "$contents" in
    *"$marker"*) ;;
    *) rm -f -- "$first" "$second"; return 1 ;;
  esac
  rm -f -- "$first" "$second"
}

service_revision="yukh-coordination-revision:$revision"
qualify "./internal/primitivesstaging/cmd/yukh-coordination-primitives" "-buildid= -X main.buildRevision=$service_revision" "$service_revision"
qualify "./internal/primitivesbootstrap/cmd/yukh-coordination-primitives-bootstrap" "-buildid= -X main.buildRevision=$revision" "$revision"
