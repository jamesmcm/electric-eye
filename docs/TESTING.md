# Testing

Run these from the repository root:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Kernel-facing testing that touches the host is run in an isolated Arch LXC
container (see [`tests/lxc/capture-test.sh`](../tests/lxc/capture-test.sh)). The daemon and workloads both run
inside an existing container, as its unprivileged test user; only the observer
receives BPF/perf/read capabilities. No mounts or package installation are done.

Ring-buffer load-test methodology, measurements and tuning guidance are in
[Performance](PERFORMANCE.md). A controlled burst generator is
available at [`tests/load/ring-burst.py`](../tests/load/ring-burst.py):

```bash
python3 tests/load/ring-burst.py --count 20000
python3 tests/load/ring-burst.py --count 30000 --path /dev/null
```

```bash
EE_LXC_NAME=ee-arch ./tests/lxc/capture-test.sh
```

The test verifies syscall failures and short writes, cwd/dirfd/symlink paths,
FD redirection, short-lived writers, aggregation beyond display limits, sensitive
reads, bulk mutation, TCP/UDP byte totals, ACCEPT endpoints, API responsiveness,
fork/exec trees and redacted arguments, package ownership, application tasks,
shared sockets, IPv4/IPv6 flows, standalone truncation, compilation/save/download-like
summaries, history after a daemon restart, and all CLI/query routes without SQLite, startup metadata supersession, cleared
`SO_ERROR`, UDP destination detection, IPv4-mapped local addresses and nondefault
TOML settings. Workloads run on a non-zero CPU.
Test artifacts are retained in fresh container directories for inspection.
MCP protocol initialization, tool discovery, structured tool calls, resource
reads, notification handling, and the Unix-socket round trip are covered by
daemon unit tests; the CLI bridge is covered by command-line parsing tests.
