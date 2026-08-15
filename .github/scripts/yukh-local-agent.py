#!/usr/bin/env python3
import argparse
import fcntl
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path


def fail(message):
    print(f"yukh-agent: {message}", file=sys.stderr)
    raise SystemExit(2)


parser = argparse.ArgumentParser()
parser.add_argument("agent")
parser.add_argument("command", nargs=argparse.REMAINDER)
parser.add_argument("--home", default=str(Path.home() / ".yukh" / "local-preview"))
args = parser.parse_args()
if not args.command:
    fail("a client command is required")
if not re.fullmatch(r"agent-[a-z](?:[a-z0-9-]{0,40}[a-z0-9])?", args.agent) or len(args.agent) > 48:
    fail("invalid agent name")

home = Path(args.home).resolve()
binary = home / "bin" / "yukh-coordination"
config = home / f"{args.agent}.json"
root_key = home / f"{args.agent}.root"
ca = home / "server.crt"
token_path = home / "supervisor.token"
for path in (binary, ca, token_path):
    if not path.is_file():
        fail(f"missing {path}")
token = token_path.read_text(encoding="ascii")

lock_path = home / "agents.lock"
lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
with os.fdopen(lock_fd, "r+b") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    roots = [path for path in home.glob("agent-*.root") if path.is_file() and not path.is_symlink()]
    if not root_key.exists():
        if len(roots) >= 32:
            fail("agent limit reached")
        fd = os.open(root_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
    if root_key.is_symlink() or not root_key.is_file():
        fail("invalid root key")
    if not config.exists():
        request = urllib.request.Request(
            "https://127.0.0.1:7444/local-preview/v1/config",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(ca)), timeout=10) as response:
                metadata = json.loads(response.read(65537))
        except Exception:
            fail("supervisor metadata unavailable")
        value = {
            "schema": 1,
            "profile": args.agent,
            "base_uri": "https://127.0.0.1:7443",
            "channel_id": metadata["channel_id"],
            "channel_uri": metadata["channel_uri"],
            "transcript_epoch": metadata["transcript_epoch"],
            "page_limit": 100,
            "max_records": 1000,
            "watch_deadline_ms": 900000,
            "source_uri": f"https://client.local/{args.agent}",
            "participant": {"id": f"agent:{args.agent.removeprefix('agent-')}", "kind": "agent"},
            "custody_database": str(home / f"{args.agent}.db"),
            "ca_certificate": str(ca),
            "receipt_keys": [{"key_id": metadata["receipt_key_id"], "public_key": metadata["receipt_key"]}],
        }
        fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"))
    if config.is_symlink() or not config.is_file():
        fail("invalid agent config")

root = root_key.read_bytes()
if len(root) != 32:
    fail("invalid root key")
root_read, root_write = os.pipe()
os.write(root_write, root)
os.close(root_write)

bootstrap = args.command == ["session", "bootstrap"]
client_socket = supervisor_socket = None
command = [str(binary), "--config", str(config), "--root-key-fd", str(root_read)]
pass_fds = [root_read]
if bootstrap:
    client_socket, supervisor_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    command.extend(["--external-token-fd", str(client_socket.fileno())])
    pass_fds.append(client_socket.fileno())
command.extend(args.command)

process = subprocess.Popen(command, pass_fds=tuple(pass_fds))
os.close(root_read)
if client_socket is not None:
    client_socket.close()
if supervisor_socket is not None:
    request = b""
    while not request.endswith(b"\n") and len(request) <= 1024:
        chunk = supervisor_socket.recv(1025 - len(request))
        if not chunk:
            break
        request += chunk
    if not request.endswith(b"\n") or len(request) > 1024:
        process.kill()
        fail("invalid client supervisor request")
    url = f"https://127.0.0.1:7444/local-preview/v1/external-token/{args.agent}"
    outbound = urllib.request.Request(url, data=request[:-1], method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(outbound, context=ssl.create_default_context(cafile=str(ca)), timeout=10) as response:
            payload = response.read(65537)
    except Exception:
        process.kill()
        fail("token supervisor unavailable")
    if len(payload) == 0 or len(payload) > 65536:
        process.kill()
        fail("invalid token supervisor response")
    json.loads(payload)
    supervisor_socket.sendall(payload)
    supervisor_socket.shutdown(socket.SHUT_WR)
    supervisor_socket.close()

raise SystemExit(process.wait())
