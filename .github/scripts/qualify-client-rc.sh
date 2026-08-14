#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
version="${1:-0.1.0-rc.2}"
case "$version" in *[!0-9A-Za-z.-]*|'') echo "invalid version" >&2; exit 2;; esac
go test ./internal/clientcli -run '^TestExecutableBootstrapsThroughSupervisorAndPersistsSession$' -count=10
go test ./internal/relay/runtime -run '^TestTwoIsolatedCLIProcessesShareOnlyTheRelayTranscript$' -count=1
output="$(mktemp -d "$root/.qualification-client-package.XXXXXXXXXX")"
trap 'rm -rf -- "$output"' EXIT
"$root/.github/scripts/package-client-rc.sh" "$version" "$output"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output" && sha256sum --check "SHA256SUMS-$version")
else
  (cd "$output" && shasum -a 256 -c "SHA256SUMS-$version")
fi
printf 'client-rc: PASS version=%s bootstrap=10 two-session-flow=1 packages=linux-amd64,linux-arm64,darwin-amd64,darwin-arm64\n' "$version"
