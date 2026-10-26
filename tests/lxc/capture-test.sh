#!/usr/bin/env bash
# Isolated kernel-capture smoke test.
#
# The daemon runs on the host (it needs to load BPF into the kernel), while the
# synthetic workload runs inside an Arch Linux LXC container. Pinning the
# workload to a non-zero CPU catches the classic "perf attachment only sees CPU
# 0" regression without running test processes directly on the host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="${EE_LXC_NAME:-ee-capture-test}"
CPU="${EE_TEST_CPU:-5}"
LOG="$(mktemp /tmp/electric-eye-lxc.XXXXXX)"
SOCKET="$(mktemp -u /tmp/electric-eye-lxc.XXXXXX.sock)"
DAEMON_PID=""
CREATED=0

cleanup() {
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    sudo kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  rm -f "$LOG" "$SOCKET"
}
trap cleanup EXIT

if ! sudo lxc-info -n "$NAME" >/dev/null 2>&1; then
  echo "==> creating Arch LXC container $NAME"
  sudo lxc-create -t download -n "$NAME" -- -d archlinux -r current -a amd64
  sudo sed -i 's/^lxc.net.0.type =.*/lxc.net.0.type = none/' \
    "/var/lib/lxc/$NAME/config"
  CREATED=1
fi

if [[ "$(sudo lxc-info -n "$NAME" -s -H)" != "RUNNING" ]]; then
  sudo lxc-start -n "$NAME" -d
fi

for _ in $(seq 1 30); do
  if sudo lxc-attach -n "$NAME" -- true >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cd "$ROOT"
echo "==> building userspace and eBPF object"
cargo xtask build-ebpf >/dev/null
cargo build --release -p electric-eyed -p electric-eye-cli >/dev/null

echo "==> starting daemon (socket $SOCKET)"
sudo stdbuf -oL -eL ./target/release/electric-eyed \
  --json --socket "$SOCKET" >"$LOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do
  if grep -q "streaming events:" "$LOG"; then
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "daemon exited during startup:" >&2
    cat "$LOG" >&2
    exit 1
  fi
  sleep 0.2
done

if ! grep -q "streaming events:" "$LOG"; then
  echo "daemon did not reach streaming state:" >&2
  cat "$LOG" >&2
  exit 1
fi

MARKER="/tmp/electric-eye-lxc-$$"
PORT="${EE_TEST_PORT:-$((20000 + ($$ % 20000)))}"
echo "==> running workload on guest CPU $CPU"
sudo lxc-attach -n "$NAME" -- taskset -c "$CPU" sh -c "
set -e
echo payload > '$MARKER'
touch '$MARKER.touch'
mv '$MARKER' '$MARKER.renamed'
rm '$MARKER.renamed' '$MARKER.touch'
"
sudo lxc-attach -n "$NAME" -- sh -c "
python3 -m http.server '$PORT' --bind 127.0.0.1 >/tmp/ee-lxc-http.log 2>&1 &
srv=\$!
sleep 0.7
taskset -c '$CPU' curl -s --max-time 2 http://127.0.0.1:'$PORT'/ >/dev/null
sleep 0.5
kill \$srv 2>/dev/null || true
wait \$srv 2>/dev/null || true
"

for _ in $(seq 1 50); do
  if grep -q "$MARKER" "$LOG"; then
    break
  fi
  sleep 0.2
done

# Actual write events are aggregated into a 5-second window.
for _ in $(seq 1 60); do
  if grep "$MARKER" "$LOG" | grep -q '"event":"file_write"'; then
    break
  fi
  sleep 0.2
done

fail=0
for expected in '"event":"file_open"' '"event":"file_write"' \
  '"event":"file_rename"' '"event":"file_unlink"' "$MARKER"; do
  if ! grep -q "$expected" "$LOG"; then
    echo "missing expected output: $expected" >&2
    fail=1
  fi
done

if ! grep -q '"event":"accept"' "$LOG"; then
  echo "missing ACCEPT event" >&2
  fail=1
elif ! grep '"event":"accept"' "$LOG" | grep -q '"comm":"python3"'; then
  echo "ACCEPT attribution did not identify the python server" >&2
  fail=1
fi

echo "==> checking query API"
if ! sudo ./target/release/electric-eye --socket "$SOCKET" status \
  | grep -q '"attached_probes"'; then
  echo "status API did not respond" >&2
  fail=1
fi

echo "==> stopping daemon"
sudo kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || true
DAEMON_PID=""

if [[ -e "$SOCKET" ]]; then
  echo "socket was not removed on SIGTERM: $SOCKET" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "--- captured events ---" >&2
  grep "$MARKER\|daemon\|error" "$LOG" >&2 || true
  exit 1
fi

echo "capture test passed (CPU $CPU, container $NAME)"
if [[ "$CREATED" == 1 ]]; then
  echo "container left running for reuse: $NAME"
fi
