#!/usr/bin/env python3
import argparse
import json
import os
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
parser.add_argument("agent", choices=("agent-a", "agent-b"))
parser.add_argument("command", nargs=argparse.REMAINDER)
parser.add_argument("--home", default=str(Path.home() / ".yukh" / "local-preview"))
args = parser.parse_args()
if not args.command:
    fail("a client command is required")

home = Path(args.home).resolve()
binary = home / "bin" / "yukh-coordination"
config = home / f"{args.agent}.json"
root_key = home / f"{args.agent}.root"
ca = home / "server.crt"
token = (home / "supervisor.token").read_text(encoding="ascii")
for path in (binary, config, root_key, ca):
    if not path.is_file():
        fail(f"missing {path}")

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
