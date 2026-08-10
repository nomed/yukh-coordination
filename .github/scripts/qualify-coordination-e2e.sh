#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

go test ./internal/relay/runtime \
  -run '^TestTwoIsolatedCLIProcessesShareOnlyTheRelayTranscript$' \
  -count=1
node --test js/test/replay.test.mjs
python3 conformance/cross-runtime/run.py

echo "coordination-e2e: PASS processes=3 clients=4 transport=HTTPS+SSE storage=memory ports=1-ephemeral transcript_records=15 fence=wrong-recipient"
