#!/usr/bin/env bash
set -euo pipefail

readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly compose="$root/.github/preview/compose.yaml"
readonly runtime="${YUKH_PREVIEW_RUNTIME:-$HOME/.yukh/local-preview}"

fail() { echo "yukh-preview: $*" >&2; exit 2; }
if [[ "$(uname -s)" != Darwin && "${YUKH_ALLOW_LINUX_QUALIFICATION:-0}" != 1 ]]; then
  fail "macOS is required"
fi
command -v docker >/dev/null || fail "Docker Desktop is required"
command -v openssl >/dev/null || fail "openssl is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v go >/dev/null || fail "Go 1.26 is required"
case "$(go env GOVERSION)" in go1.26*) ;; *) fail "Go 1.26 is required";; esac

export YUKH_PREVIEW_RUNTIME="$runtime"
export YUKH_UID="$(id -u)"
export YUKH_GID="$(id -g)"
compose_command=(docker compose -f "$compose")

case "${1:-}" in
  up)
    install -d -m 0700 "$runtime" "$runtime/bin"
    if [[ ! -f "$runtime/server.key" || ! -f "$runtime/server.crt" ]]; then
      openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2 \
        -keyout "$runtime/server.key" -out "$runtime/server.crt" \
        -config "$root/.github/preview/openssl.cnf" >/dev/null 2>&1
    fi
    python3 - "$runtime" <<'PY'
import os, secrets, sys
from pathlib import Path
home = Path(sys.argv[1])
values = {
    "supervisor.token": secrets.token_urlsafe(32).encode("ascii"),
    "receipt-signing.key": secrets.token_bytes(32),
    "agent-a.root": secrets.token_bytes(32),
    "agent-b.root": secrets.token_bytes(32),
}
for name, value in values.items():
    path = home / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
PY
    chmod 0600 "$runtime/server.key" "$runtime/server.crt" "$runtime/supervisor.token" \
      "$runtime/receipt-signing.key" "$runtime/agent-a.root" "$runtime/agent-b.root"
    python3 - "$runtime" <<'PY'
import json, os, sys
from pathlib import Path
home = Path(sys.argv[1]).resolve()
value = {
    "profile": "yukh-coordination/local-preview-runtime-v1",
    "public_base_uri": "https://127.0.0.1:7443",
    "public_bind": "0.0.0.0:7443",
    "supervisor_bind": "0.0.0.0:7444",
    "nats_url": "nats://nats:4222",
    "tls_certificate": "/run/yukh/server.crt",
    "tls_private_key": "/run/yukh/server.key",
    "supervisor_token": "/run/yukh/supervisor.token",
    "receipt_signing_key": "/run/yukh/receipt-signing.key",
}
path = home / "coordinator.json"
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(value, stream, separators=(",", ":"))
PY
    echo "Building native client"
    (cd "$root" && go build -trimpath -buildvcs=false -ldflags '-buildid= -X github.com/nomed/yukh-coordination/internal/clientcli.Version=0.1.0-rc.2-dev' -o "$runtime/bin/yukh-coordination" ./internal/clientcli/cmd/yukh-coordination)
    chmod 0700 "$runtime/bin/yukh-coordination"
    "${compose_command[@]}" up --build -d --wait --wait-timeout 60
    metadata=""
    for _ in {1..30}; do
      if metadata="$(curl -fsS --cacert "$runtime/server.crt" -H "Authorization: Bearer $(<"$runtime/supervisor.token")" https://127.0.0.1:7444/local-preview/v1/config 2>/dev/null)"; then
        break
      fi
      sleep 1
    done
    if [[ -z "$metadata" ]]; then
      "${compose_command[@]}" ps >&2
      "${compose_command[@]}" logs coordinator >&2
      fail "coordinator supervisor did not become ready"
    fi
    YUKH_METADATA="$metadata" python3 - "$runtime" <<'PY'
import json, os, sys
from pathlib import Path
home = Path(sys.argv[1]).resolve()
metadata = json.loads(os.environ["YUKH_METADATA"])
for slot in ("agent-a", "agent-b"):
    value = {
        "schema": 1,
        "profile": slot,
        "base_uri": "https://127.0.0.1:7443",
        "channel_id": metadata["channel_id"],
        "channel_uri": metadata["channel_uri"],
        "transcript_epoch": metadata["transcript_epoch"],
        "page_limit": 100,
        "max_records": 1000,
        "watch_deadline_ms": 900000,
        "source_uri": f"https://client.local/{slot}",
        "participant": {"id": f"agent:{slot[-1]}", "kind": "agent"},
        "custody_database": str(home / f"{slot}.db"),
        "ca_certificate": str(home / "server.crt"),
        "receipt_keys": [{"key_id": metadata["receipt_key_id"], "public_key": metadata["receipt_key"]}],
    }
    path = home / f"{slot}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"))
PY
    echo "yukh-preview: READY"
    echo "$root/.github/scripts/yukh-local-agent.py agent-a session bootstrap"
    echo "$root/.github/scripts/yukh-local-agent.py agent-b session bootstrap"
    ;;
  down)
    "${compose_command[@]}" down --volumes --remove-orphans
    rm -f -- "$runtime/coordinator.json" "$runtime/server.crt" "$runtime/server.key" "$runtime/supervisor.token" \
      "$runtime/receipt-signing.key" \
      "$runtime/agent-a.json" "$runtime/agent-b.json" "$runtime/agent-a.root" "$runtime/agent-b.root" \
      "$runtime/agent-a.db" "$runtime/agent-a.db-shm" "$runtime/agent-a.db-wal" \
      "$runtime/agent-b.db" "$runtime/agent-b.db-shm" "$runtime/agent-b.db-wal"
    python3 - "$runtime" <<'PY'
import re, sys
from pathlib import Path
import shutil
home = Path(sys.argv[1]).resolve()
pattern = re.compile(r"agent-[a-z](?:[a-z0-9-]{0,40}[a-z0-9])?\.(?:json|root|db|db-shm|db-wal)")
for path in home.iterdir():
    if pattern.fullmatch(path.name):
        path.unlink(missing_ok=True)
(home / "agents.lock").unlink(missing_ok=True)
shutil.rmtree(home / "stale-agents", ignore_errors=True)
PY
    [[ -z "$("${compose_command[@]}" ps -aq)" ]] || fail "containers remain after teardown"
    [[ -z "$(docker network ls --filter label=com.docker.compose.project=yukh-local-preview -q)" ]] || fail "network remains after teardown"
    [[ -z "$(docker volume ls --filter label=com.docker.compose.project=yukh-local-preview -q)" ]] || fail "volume remains after teardown"
    echo "yukh-preview: REMOVED containers=1 network=1 volumes=1 credentials=1"
    ;;
  status)
    "${compose_command[@]}" ps
    ;;
  *) fail "usage: $0 up|status|down";;
esac
