#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

test "$(uname -s)" = Darwin || { echo "macOS is required" >&2; exit 2; }
for command in go nats-server node python3; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done
case "$(go env GOVERSION)" in go1.26*) ;; *) echo "Go 1.26 is required" >&2; exit 2;; esac

YUKH_NATS_SERVER="$(command -v nats-server)" go test -race \
  ./internal/relay/jetstream ./internal/coordination/jetstreamkv
.github/scripts/qualify-coordination-e2e.sh
.github/scripts/qualify-client-rc.sh

printf 'macos-local: PASS jetstream=local client=darwin-amd64,darwin-arm64 coordinator=hermetic-test-runtime\n'
