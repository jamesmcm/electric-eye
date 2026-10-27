#!/usr/bin/env python3
"""A process present before attachment must retain its inventoried metadata."""
import json
import os
from pathlib import Path
import socket
import sys
import time

stage = Path(sys.argv[1])
(stage / "inventory.pid").write_text(str(os.getpid()))
for _ in range(600):
    if (stage / "inventory-trigger").exists():
        break
    time.sleep(0.05)
else:
    raise AssertionError("startup inventory trigger timed out")

(stage / "inventory-write").write_text("observed")
for _ in range(100):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(str(stage / "eye.sock"))
        stream.sendall(json.dumps({"op": "process", "process": str(os.getpid())}).encode() + b"\n")
        data = b""
        while chunk := stream.recv(65536):
            data += chunk
    rows = json.loads(data)["processes"]
    exact = next((p for p in rows if p["identity_exact"]), None)
    if exact:
        assert exact["argv"] and any("startup.py" in a for a in exact["argv"]), exact
        assert exact["cwd"] == os.getcwd(), exact
        (stage / "inventory-result.json").write_text(json.dumps(exact))
        print("Startup argv and cwd survived exact identity supersession", flush=True)
        break
    time.sleep(0.05)
else:
    raise AssertionError("process did not acquire an exact kernel identity")
