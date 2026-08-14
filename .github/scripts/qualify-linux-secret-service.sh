#!/usr/bin/env bash
set -euo pipefail

readonly image="golang:1.26-bookworm@sha256:db25d241820546be7b96953eea8d3e6bd15d413d59d00a75b68b74dfb5e2ecd2"
readonly snapshot="20240311T000000Z"
readonly tag="yukh-secret-service-qualification-$$"
readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository="$(cd -- "$script_dir/../.." && pwd -P)"
built=0

usage() {
  cat <<'EOF'
Usage:
  .github/scripts/qualify-linux-secret-service.sh --run-gnome-keyring
  .github/scripts/qualify-linux-secret-service.sh --keepassxc-manual

--run-gnome-keyring is the only command that downloads a public image and
packages, builds an ephemeral Linux image, and starts a temporary private D-Bus
and GNOME Keyring service. It runs with no network after the image build and
removes its temporary image and container state on exit.

KeePassXC Secret Service needs an unlocked GUI/daemon and cannot be safely
started headlessly by this harness. --keepassxc-manual prints the gated command
for a dedicated temporary KeePassXC database and private D-Bus session; it
does not claim qualification.
EOF
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$built" == 1 ]]; then
    docker image rm --force "$tag" >/dev/null 2>&1 || true
  fi
  exit "$status"
}

keepassxc_manual() {
  cat <<'EOF'
KeePassXC was not run. Its Secret Service integration requires an explicitly
unlocked GUI/daemon and a dedicated disposable KeePassXC database. Do not use
a host session bus or a personal collection. Once a reviewer has created a
private D-Bus socket and selected the exact collection, run on Linux:

  env -u DBUS_SESSION_BUS_ADDRESS \
    YUKH_SECRET_SERVICE_QUALIFICATION=keepassxc \
    YUKH_SECRET_SERVICE_QUALIFICATION_BUS_SOCKET=/absolute/private/bus \
    YUKH_SECRET_SERVICE_QUALIFICATION_COLLECTION=/org/freedesktop/secrets/collection/EXACT \
    go test ./internal/clientauth/secretservice \
      -run '^TestRealSecretServiceQualification$' -count=1

The test creates a disposable root item and locks the configured collection; it
never invokes a Secret Service Prompt. Destroy the private bus and KeePassXC
database after the run. A prompt returned by the lock operation is a failure,
not evidence of a pass.
EOF
}

if [[ $# != 1 ]]; then
  usage >&2
  exit 2
fi

case "$1" in
  --help|-h)
    usage
    exit 0
    ;;
  --keepassxc-manual)
    keepassxc_manual
    exit 2
    ;;
  --run-gnome-keyring)
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ ! -f "$repository/go.mod" ]] || [[ ! -x "$script_dir/qualify-linux-secret-service-inner.sh" ]]; then
  echo "run from a checkout containing the Secret Service qualification scripts" >&2
  exit 2
fi
if ! command -v docker >/dev/null; then
  echo "Docker is required only for --run-gnome-keyring" >&2
  exit 1
fi

trap cleanup EXIT INT TERM
echo "Qualifying GNOME Keyring from $image with Debian snapshot $snapshot"
built=1
docker build --platform linux/amd64 --no-cache --force-rm --rm --tag "$tag" --file - "$repository" <<EOF
FROM --platform=linux/amd64 $image
RUN rm -f /etc/apt/sources.list.d/debian.sources && \\
    printf '%s\\n' \\
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$snapshot/ bookworm main' \\
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/$snapshot/ bookworm-security main' \\
      > /etc/apt/sources.list && \\
    apt-get -o Acquire::Check-Valid-Until=false update && \\
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends dbus gnome-keyring && \\
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY .github/scripts/qualify-linux-secret-service-inner.sh .github/scripts/qualify-linux-secret-service-inner.sh
CMD [".github/scripts/qualify-linux-secret-service-inner.sh"]
EOF

docker run --rm --platform linux/amd64 --network none "$tag"
