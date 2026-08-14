#!/usr/bin/env bash
set -euo pipefail

readonly state="$(pwd)/.secret-service-qualification-state"
readonly socket="$state/session-bus"
readonly collection="/org/freedesktop/secrets/collection/login"
bus_pid=""
keyring_pid=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$keyring_pid" ]] && kill -0 "$keyring_pid" 2>/dev/null; then
    kill "$keyring_pid"
  fi
  wait "$keyring_pid" 2>/dev/null || true
  if [[ -n "$bus_pid" ]] && kill -0 "$bus_pid" 2>/dev/null; then
    kill "$bus_pid"
  fi
  wait "$bus_pid" 2>/dev/null || true
  rm -rf -- "$state"
  exit "$status"
}
trap cleanup EXIT INT TERM

umask 077
mkdir -p "$state/home" "$state/runtime" "$state/data"
chmod 700 "$state" "$state/home" "$state/runtime" "$state/data"
dpkg-query --showformat='${Package}=${Version}\n' --show dbus gnome-keyring
go version
bus_address="unix:path=$socket"
env -i \
  PATH="$PATH" \
  HOME="$state/home" \
  XDG_DATA_HOME="$state/data" \
  XDG_RUNTIME_DIR="$state/runtime" \
  dbus-daemon --session --nofork --nopidfile --address="$bus_address" \
  >"$state/dbus.log" 2>&1 &
bus_pid="$!"
for _ in $(seq 1 100); do
  if [[ -S "$socket" ]] && kill -0 "$bus_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if [[ ! -S "$socket" ]] || ! kill -0 "$bus_pid" 2>/dev/null; then
  cat "$state/dbus.log" >&2
  echo "private D-Bus daemon did not create the requested socket" >&2
  exit 1
fi

printf '\n' | env -i \
  PATH="$PATH" \
  HOME="$state/home" \
  XDG_DATA_HOME="$state/data" \
  XDG_RUNTIME_DIR="$state/runtime" \
  DBUS_SESSION_BUS_ADDRESS="$bus_address" \
  gnome-keyring-daemon --login --components=secrets --control-directory="$state/runtime/keyring" \
  >"$state/gnome-keyring-login.log" 2>&1

env -i \
  PATH="$PATH" \
  HOME="$state/home" \
  XDG_DATA_HOME="$state/data" \
  XDG_RUNTIME_DIR="$state/runtime" \
  DBUS_SESSION_BUS_ADDRESS="$bus_address" \
  gnome-keyring-daemon --start --foreground --components=secrets --control-directory="$state/runtime/keyring" \
  >"$state/gnome-keyring.log" 2>&1 &
keyring_pid="$!"
for _ in $(seq 1 100); do
  if DBUS_SESSION_BUS_ADDRESS="$bus_address" dbus-send --print-reply \
    --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus \
    org.freedesktop.DBus.NameHasOwner \
    string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then
    break
  fi
  sleep 0.1
done
if ! DBUS_SESSION_BUS_ADDRESS="$bus_address" dbus-send --print-reply \
  --dest=org.freedesktop.DBus \
  /org/freedesktop/DBus \
  org.freedesktop.DBus.NameHasOwner \
  string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then
  cat "$state/dbus.log" "$state/gnome-keyring-login.log" "$state/gnome-keyring.log" >&2
  echo "GNOME Keyring did not own org.freedesktop.secrets on the private D-Bus" >&2
  exit 1
fi

env -u DBUS_SESSION_BUS_ADDRESS \
  YUKH_SECRET_SERVICE_QUALIFICATION=gnome-keyring \
  YUKH_SECRET_SERVICE_QUALIFICATION_BUS_SOCKET="$socket" \
  YUKH_SECRET_SERVICE_QUALIFICATION_COLLECTION="$collection" \
  go test ./internal/clientauth/secretservice \
    -run '^TestRealSecretServiceQualification$' -count=1 -v
