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
    for source,name in [("target/debug/electric-eyed","electric-eyed"),("target/debug/electric-eye","electric-eye"),("target/bpfel-unknown-none/release/electric-eye-ebpf","ebpf"),("tests/lxc/regressions.py","regressions.py")]:
        archive.add(source,arcname=name)
PY
start_daemon() {
  local log="$1"
  sudo -n lxc-attach -n "$NAME" -- setpriv \
    --reuid="$TEST_UID" --regid="$TEST_GID" --clear-groups \
    --inh-caps=+bpf,+perfmon,+dac_read_search,+sys_ptrace \
    --ambient-caps=+bpf,+perfmon,+dac_read_search,+sys_ptrace \
    sh -c 'echo $$ > "$1/daemon.pid"; exec "$1/electric-eyed" --json --socket "$1/eye.sock" --db "$1/eye.db" --ebpf-object "$1/ebpf"' sh "$STAGE" \
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
CPU="${EE_TEST_CPU:-$(guest python3 -c 'import os; c=sorted(os.sched_getaffinity(0)); print(next((n for n in c if n>0),c[0]))')}"
guest taskset -c "$CPU" python3 "$STAGE/regressions.py" "$STAGE/eye.sock" | tee "$LOG_DIR/results.json"
# Check that complete incident identity survives a real daemon restart.
stop_daemon
start_daemon "$LOG_DIR/restarted.log"
guest python3 -c '
import socket,json,sys
with socket.socket(socket.AF_UNIX) as s:
    s.connect(sys.argv[1]);s.sendall(b"{\"op\":\"incidents\",\"limit\":1000}\n");data=b""
    while chunk:=s.recv(65536):data+=chunk
incidents=json.loads(data)["incidents"]
assert any(i.get("path") and i.get("exe") and i.get("process",{}).get("start_ns") and i.get("id") for i in incidents), incidents
print("Incident identity survived restart")
' "$STAGE/eye.sock"
stop_daemon
if guest test -e "$STAGE/eye.sock"; then echo "socket survived daemon shutdown" >&2; exit 1; fi
printf 'Capture regressions passed on CPU %s; logs: %s; guest artifacts: %s\n' "$CPU" "$LOG_DIR" "$STAGE"
