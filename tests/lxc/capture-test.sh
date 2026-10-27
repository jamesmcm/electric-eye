#!/usr/bin/env bash
# All observer/workload processes run in an existing LXC PID namespace. Root
# is used only to enter it and grant capabilities before dropping to the test
# UID. No mounts, package installs, host collectors, or root file writes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="${EE_LXC_NAME:-ee-arch}"
TEST_UID="${EE_LXC_UID:-1000}"
TEST_GID="${EE_LXC_GID:-1000}"
LOG_DIR="$(mktemp -d /tmp/electric-eye-capture.XXXXXX)"
DAEMON_JOB=""
INVENTORY_JOB=""
STAGE=""
guest() {
  sudo -n lxc-attach -n "$NAME" -- setpriv \
    --reuid="$TEST_UID" --regid="$TEST_GID" --clear-groups "$@"
}
stop_daemon() {
  if [[ -n "$STAGE" ]]; then
    guest python3 -c '
import os,signal,socket,json,sys
from pathlib import Path
try:
    pid=int(Path(sys.argv[1]).read_text())
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(2);stream.connect(str(Path(sys.argv[1]).parent/"eye.sock"))
        stream.sendall(b"{\"op\":\"status\"}\n");data=b""
        while chunk:=stream.recv(65536):data+=chunk
    if json.loads(data)["pid"]==pid:os.kill(pid,signal.SIGTERM)
except (FileNotFoundError,ProcessLookupError,ConnectionRefusedError): pass
' "$STAGE/daemon.pid" || true
  fi
  if [[ -n "$DAEMON_JOB" ]]; then wait "$DAEMON_JOB" || true; DAEMON_JOB=""; fi
}
trap stop_daemon EXIT

if [[ "$(sudo -n lxc-info -n "$NAME" -s -H)" != RUNNING ]]; then
  echo "An existing running LXC container is required: $NAME" >&2
  exit 1
fi
guest python3 --version
STAGE="$(guest mktemp -d /tmp/electric-eye-regression.XXXXXX)"
cd "$ROOT"
cargo xtask build-ebpf
cargo build --locked -p electric-eyed -p electric-eye-cli
# Pipes keep lxc-attach from changing ownership on host artifact descriptors.
python3 - <<'PY' | guest tar -xf - -C "$STAGE"
import sys,tarfile
with tarfile.open(fileobj=sys.stdout.buffer,mode="w|") as archive:
    for source,name in [("tests/lxc/startup.py","startup.py"),("target/debug/electric-eyed","electric-eyed"),("target/debug/electric-eye","electric-eye"),("target/bpfel-unknown-none/release/electric-eye-ebpf","ebpf"),("tests/lxc/regressions.py","regressions.py"),("tests/lxc/usability.py","usability.py")]:
        archive.add(source,arcname=name)
PY
# Nondefault TOML values exercise loader map sizes and userspace settings.
guest python3 -c 'import sys;from pathlib import Path;Path(sys.argv[1]).write_text("[limits]\naggregation_ms=1000\napi_workers=3\nactivity_entries=4096\n[capture]\nring_bytes=33554432\npending_entries=4096\n[rules]\nsensitive_window_ms=45000\ndedup_window_ms=120000\n")' "$STAGE/config.toml"
guest python3 "$STAGE/startup.py" "$STAGE" 2>&1 | tee "$LOG_DIR/inventory.log" &
INVENTORY_JOB=$!
for _ in $(seq 1 100); do
  if guest test -e "$STAGE/inventory.pid"; then break; fi
  sleep 0.05
done
start_daemon() {
  local log="$1"
  local mode="${2:-persist}"
  sudo -n lxc-attach -n "$NAME" -- setpriv \
    --reuid="$TEST_UID" --regid="$TEST_GID" --clear-groups \
    --inh-caps=+bpf,+perfmon,+dac_read_search,+sys_ptrace \
    --ambient-caps=+bpf,+perfmon,+dac_read_search,+sys_ptrace \
    sh -c 'echo $$ > "$1/daemon.pid"; if [ "$2" = memory ]; then exec "$1/electric-eyed" --json --config "$1/config.toml" --socket "$1/eye.sock" --no-db --ebpf-object "$1/ebpf"; else exec "$1/electric-eyed" --json --config "$1/config.toml" --socket "$1/eye.sock" --db "$1/eye.db" --ebpf-object "$1/ebpf"; fi' sh "$STAGE" "$mode" \
    2>&1 | tee "$log" >/dev/null &
  DAEMON_JOB=$!
  for _ in $(seq 1 100); do
    if rg -q 'streaming events:' "$log"; then return; fi
    if ! kill -0 "$DAEMON_JOB" 2>/dev/null; then tail -30 "$log" >&2; return 1; fi
    sleep 0.1
  done
  tail -30 "$log" >&2
  return 1
}
start_daemon "$LOG_DIR/capture.log"
guest python3 -c '
import json,socket,sys
from pathlib import Path
stage=Path(sys.argv[1]);pid=(stage/"inventory.pid").read_text()
with socket.socket(socket.AF_UNIX) as s:
    s.connect(str(stage/"eye.sock"));s.sendall(json.dumps(dict(op="process",process=pid)).encode()+b"\n");data=b""
    while chunk:=s.recv(65536):data+=chunk
rows=json.loads(data)["processes"]
assert any(p["source"]=="inventory" and p["argv"] for p in rows),rows
(stage/"inventory-trigger").touch()
' "$STAGE"
wait "$INVENTORY_JOB"
INVENTORY_JOB=""
CPU="${EE_TEST_CPU:-$(guest python3 -c 'import os; c=sorted(os.sched_getaffinity(0)); print(next((n for n in c if n>0),c[0]))')}"
guest taskset -c "$CPU" python3 "$STAGE/regressions.py" "$STAGE/eye.sock" | tee "$LOG_DIR/results.json"
# Check that complete incident identity survives a real daemon restart.
WORKLOAD_PID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pid"])' "$LOG_DIR/results.json")"
stop_daemon
start_daemon "$LOG_DIR/restarted.log"
guest python3 -c '
import socket,json,sys
def query(op,**fields):
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(sys.argv[1]);s.sendall(json.dumps(dict(op=op,**fields)).encode()+b"\n");data=b""
        while chunk:=s.recv(65536):data+=chunk
    return json.loads(data)
incidents=query("incidents",limit=1000)["incidents"]
assert any(i.get("path") and i.get("exe") and i.get("process",{}).get("start_ns") and i.get("id") for i in incidents), incidents
process=query("process",process=sys.argv[2])["processes"]
assert process and process[0]["exited_ms"] and process[0]["argv"] and process[0]["package"]["package"],process
assert query("process",process=sys.argv[2])["execs"]
assert len(query("tree",process=sys.argv[2])["processes"])>1
flows=query("flows",limit=1000)["flows"]
assert any(f["sent"] and f["received"] and f["closed_ms"] for f in flows),flows
summaries=query("summaries",limit=1000)["summaries"]
assert any(s["kind"]=="build_session" and s["evidence"] and s["root_exit_code"]==0 for s in summaries),summaries
assert query("apps")["tasks"]
assert any(e["event"].get("comm")=="ee-regression" for e in query("activity",limit=1000)["activity"])
print("Process/exec trees, package snapshots, application tasks, flows, summaries and incidents survived restart")
' "$STAGE/eye.sock" "$WORKLOAD_PID"

stop_daemon
start_daemon "$LOG_DIR/memory.log" memory
guest taskset -c "$CPU" python3 "$STAGE/usability.py" "$STAGE"
stop_daemon
if guest test -e "$STAGE/eye.sock"; then echo "socket survived daemon shutdown" >&2; exit 1; fi
printf 'Capture regressions passed on CPU %s; logs: %s; guest artifacts: %s\n' "$CPU" "$LOG_DIR" "$STAGE"
