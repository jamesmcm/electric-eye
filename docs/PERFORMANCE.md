# Performance and load testing

This document records the ring-buffer load testing done on 2026-10-30 and the
tuning rules that follow from it. It is a functional burst test, not a
sustained system-wide throughput benchmark.

## Test environment

- Arch Linux, x86_64, with the required BPF and tracefs support
- A desktop with sufficient memory for the tested ring sizes
- `electric-eye.service` running as the unprivileged `electric-eye` user
- Event ABI v4
- `capture.ring_bytes = 268435456` (256 MiB) for the final run
- SQLite persistence enabled; raw retention 5 minutes, activity retention 30 days
- Concurrent interactive, network, and build workloads

The host was deliberately not quiesced. Results therefore show burst behavior
under real background load, not a clean-room maximum.

## Metrics

`electric-eye --json status` exposes:

- `events_total` — activity entries delivered to the daemon/query layer.
- `store.raw_events` — raw rows currently retained in SQLite.
- `store.activities` — retained activity rollups.
- `store.dropped` — events or documents dropped because the SQLite writer queue
  was full.
- `capture_loss` — kernel-side counters, in order:

  | Index | Name | Meaning |
  | --- | --- | --- |
  | 0 | ring | Event could not reserve ring space; event lost |
  | 1 | pending | Syscall/network pending-map insertion failed |
  | 2 | identity | Kernel process identity capture failed |
  | 3 | path | File event was recorded but its path is unresolved |

  A path failure is not a lost event: the event is still submitted with a
  synthetic `unresolved:` path and uncertainty label. Ring/pending/identity
  losses are actual capture gaps.

CPU and memory were sampled from systemd and `/proc/<pid>/stat`:

```bash
systemctl show -p MemoryCurrent -p MemoryPeak -p CPUUsageNSec electric-eye.service
ps -o pid,etime,%cpu,%mem,rss,nlwp,stat -p "$(systemctl show -p MainPID --value electric-eye.service)"
```

## Reproduction

Generate a controlled open/close burst:

```bash
python3 tests/load/ring-burst.py --count 20000
python3 tests/load/ring-burst.py --count 30000 --path /dev/null
```

Capture before/after counters:

```bash
electric-eye --json status
python3 tests/load/ring-burst.py --count 100000
sleep 5
electric-eye --json status
```

For CPU time during the burst, read `/proc/<pid>/stat` fields 14 and 15
(`utime` and `stime`) before and after; 100 ticks is one second on the default
`USER_HZ=100`.

The generated file is a temporary file under `/tmp` (unless `--path` is
given). The script removes it after the run. It intentionally avoids package or
system changes; run disruptive variants in an isolated LXC container instead of
on a host you care about.

## Results

All numbers are a single observed run under the background load above. They are
useful for relative comparisons and for catching regressions, not as promises
of throughput on other machines. Ring-loss and path-failure columns are
**deltas for the test window**; absolute counters can include background
activity.

| Test | Burst | Delivered events | Ring loss | Path failures | CPU time | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 30k opens of `/dev/null` | 0.09s | ~0 (filtered) | 0 | 0 | not measured | Kernel noise filter removed them before the ring |
| 20k opens of a `/tmp` file | 0.06s | ~21k | **0** | 0 | ~0.45s | No storage drops; absolute path-failure count was 15 |
| 100k opens of a `/tmp` file, 64 MiB ring | 0.23s | ~41k | **61,172** | 0 | ~1.25s | Burst exceeded ring capacity |
| 100k opens of a `/tmp` file, 256 MiB ring | 0.28s | ~97k | **3,068** | 0 | ~2.04s | Same burst nearly absorbed; store queue dropped 6,600 |
| 30 × `bash -c true` | ~instant | small | 0 | **0** | — | Failed `/dev/tty` opens no longer produce empty paths |
| memfd open/truncate | instant | 1 | 0 | 2 | — | Synthetic path retained `fd=3`, `inode=2632`, `dev=1` |

The 100k/0.28s burst is approximately **350k events/s** at the kernel source.
The measured userspace consumer rate in the 20k test was roughly **40k
events/s**. A ring can only absorb a burst while the consumer catches up; it
cannot raise that long-term rate.

## What made the difference

### 1. Kernel-side filtering

`ignore_paths` and `capture.noise_paths` are inserted into the BPF
`IGNORE_PREFIXES` LPM trie. When a resolved file path matches, the event is
discarded in `sys_exit` before ring submission. Renames are retained unless both
sides match.

This removes whole classes of events from the ring, the userspace event loop,
the SQLite queue, and journald:

- default noise paths: `/dev/`, `/proc/`, `/sys/`, `/run/`
- every configured `ignore_paths` prefix
- both sides of a rename only when both are ignored

The 30k `/dev/null` test confirmed that these events no longer enter the ring.

### 2. Userspace fast path

Before these changes, every event performed a `/proc/<pid>/stat` read in
`Session::entry` to decide whether to enrich the systemd unit. That is a file
read plus parsing per event. The process registry already contains the relevant
metadata (unit, cgroup, executable, application) and `process::observe` runs
before file/network events are converted, so the per-event `/proc` lookup was
removed. A redundant full `ProcessRecord` clone in `process::observe` was also
removed, and Nix provenance lookup is skipped unless the executable is under
`/nix/store`.

A userspace early filter still checks ignored/noise paths before process
grouping and document persistence. This is a fallback for paths the kernel could
not classify, and it preserves the same rename rule.

### 3. Ring sizing

`capture.ring_bytes` is a **burst buffer**:

- 64 MiB held about 20k events comfortably in the test.
- 256 MiB held almost all of a 100k-event burst and reduced ring loss from
  ~61k to ~3k.
- 256 MiB does not help a sustained event rate above the consumer rate; it only
  delays the point at which loss begins.

The ring is allocated as BPF map memory. A 256 MiB ring increased service
memory substantially (roughly 0.5–0.7 GiB resident including caches in this
run), which may be acceptable on a high-memory host but should be an explicit choice on
smaller machines.

### 4. The next bottleneck: storage

The 256 MiB/100k run still reported **6,600 `store.dropped`** entries. The BPF
ring and userspace kept up better than the SQLite writer queue. The storage path
uses a bounded synchronous channel and `try_send`, so a full queue drops rather
than blocking capture. Document writes are batched inside transactions, and the
collector attaches only after database/baseline/inventory startup so that ring
buffering does not fill before the drain loop begins. Relevant knobs are:

- `limits.store_queue` (default 8192)
- `limits.store_batch` (default 128)
- `limits.store_flush_ms` (default 200)

Increasing the queue absorbs more burst, but it is the same trade-off as the
ring. Event and document writes are now batched inside transactions; document
writes previously autocommitted one row at a time and were the main source of
writer-queue pressure. If `store.dropped` still grows, measure writer
throughput and tune the queue/batch settings rather than silently dropping
durable history.

## Tuning checklist

1. **Measure first**

   ```bash
   electric-eye --json status
   ```

   Record `capture_loss`, `store.dropped`, `events_total`, CPU, memory, and the
   effective `config.capture.ring_bytes`.

2. **Filter before enlarging**

   Run `electric-eye noise` to get reviewable candidate prefixes, repeated-
   incident applications and noisy correlations. Add genuinely uninteresting
   prefixes to `ignore_paths` or `capture.noise_paths`. For example, a build
   workspace's `target` directory or a cache directory. Resolved paths are
   filtered in-kernel; unresolved paths still reach userspace and are marked
   uncertain.

3. **Check whether loss is a burst or sustained**

   Sample status repeatedly. If ring loss stops increasing after a spike, a
   larger ring may absorb the burst. If it keeps increasing, the consumer or
   event source is saturated; increase buffering will only postpone the
   problem.

4. **Size the ring deliberately**

   Default is 16 MiB. 64 MiB is a reasonable busy-desktop value; 256 MiB is a
   burst absorber for hosts with memory to spare. Do not treat it as a
   throughput guarantee.

5. **Then look at storage**

   If `store.dropped` grows while ring loss is small, tune `store_queue` and
   `store_batch` and measure the writer. Do not hide the problem by dropping
   durable history silently.

6. **Validate path quality separately**

   `capture_loss[3]` is path uncertainty, not event loss. Check unresolved
   events with:

   ```bash
   electric-eye --json --limit 1000 activity | python3 -c '
   import json, sys
   rows = json.load(sys.stdin)["activity"]
   for row in rows:
       if row.get("path_resolution") == "unresolved":
           print(row["event"]["event"], row["event"].get("path"))
   '
   ```

   Failed opens retry at syscall exit. Synthetic paths beginning with
   `unresolved:` may include `dirfd`, `cwd`, `fd`, `inode`, and `dev`; use those
   identifiers for correlation rather than claiming a filename.

## Interpretation limits

- These are synthetic open/close bursts, not a full workload benchmark.
- `events_total` includes unrelated background events; the burst delta is an
  approximation.
- The host was busy and not isolated. Run a controlled LXC benchmark before
  making capacity claims for a different machine or kernel.
- Ring loss counters count events, not bytes. Record sizes vary by event type
  because of path, executable, cgroup, and argv fields.
- A zero-loss run does not prove complete kernel coverage; probe attachment,
  unsupported syscalls, path uncertainty, and storage retention still matter.

## Follow-up work

- Benchmark the SQLite writer in isolation and tune queue/batch/flush values.
- Measure per-event-type userspace cost (opens, writes, mmaps, network events).
- Consider BPF-side aggregation for high-rate write/traffic events.
- Repeat the burst matrix in an isolated Arch LXC container for reproducible
  regression numbers.
- Add a small regression test that asserts the noise filter keeps `/dev` events
  out of the ring without weakening functional coverage.
