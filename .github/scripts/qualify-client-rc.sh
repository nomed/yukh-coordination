#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
go test ./internal/clientcli -run '^TestExecutableBootstrapsThroughSupervisorAndPersistsSession$' -count=10
go test ./internal/relay/runtime -run '^TestTwoIsolatedCLIProcessesShareOnlyTheRelayTranscript$' -count=1
output="$(mktemp -d "$root/.qualification-client-package.XXXXXXXXXX")"
trap 'rm -rf -- "$output"' EXIT
"$root/.github/scripts/package-client-rc.sh" 0.1.0-rc.1 "$output"
(cd "$output" && sha256sum --check "SHA256SUMS-0.1.0-rc.1")
printf 'client-rc: PASS bootstrap=10 two-session-flow=1 packages=linux-amd64,linux-arm64\n'
