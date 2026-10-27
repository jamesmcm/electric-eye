#!/usr/bin/env python3
"""Unprivileged recent-history/CLI smoke check for a --no-db observer."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

stage = Path(sys.argv[1])
endpoint = str(stage / "eye.sock")
cli = str(stage / "electric-eye")

def query(op, **fields):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(endpoint)
        stream.sendall(json.dumps(dict(op=op, **fields)).encode() + b"\n")
        data = b""
        while chunk := stream.recv(65536):
            data += chunk
    result = json.loads(data)
    assert "error" not in result, result
    return result

def command(*args):
    return subprocess.check_output([cli, "--socket", endpoint, *args], text=True)

root = Path(tempfile.mkdtemp(prefix="memory-usability-", dir=stage))
path = root / "saved"
path.write_bytes(b"readable")
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.bind(("127.0.0.1", 0))
    udp.sendto(b"local", udp.getsockname())
    assert udp.recv(100) == b"local"
(root / "after-receive").write_bytes(b"observed")
time.sleep(6)
assert query("status")["store"] is None
actor = query("process", process=str(os.getpid()))
assert actor["execs"] and actor["processes"]
for op in ("file", "why"):
    activity = query(op, path=str(path))["activity"]
    assert any(e["event"].get("path") == str(path) for e in activity), activity
app = actor["processes"][0]["application"]
assert query("app", app=app["id"])["activity"]
assert query("network")["activity"]
assert query("flows")["flows"]
assert query("summaries")["summaries"]
assert query("apps")["tasks"]
assert "pid " in command("flows")
assert "Summary:" in command("summaries")
assert "Exec generation" in command("process", str(os.getpid()))
assert len(json.loads(command("--json", "--limit", "1", "flows"))["flows"]) == 1
assert subprocess.run([cli, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
assert subprocess.run([cli, "--version"], stdout=subprocess.DEVNULL).returncode == 0
for args in (["status", "extra"], ["--socket"], ["--limit", "0", "flows"], ["--typo"]):
    assert subprocess.run([cli, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 2, args
status = query("status")
assert not any(status["capture_loss"]), status
print("No-database file/app/network/flow/summary queries and readable CLI passed; capture losses zero")
