# electric-eyed

The eBPF collector and read-only evidence server for
[Electric Eye](https://github.com/jamesmcm/electric-eye), a Linux activity monitor.

```bash
cargo install --locked electric-eyed
```

This builds the **userspace daemon only**. Running it also requires a matching
BPF object, Linux 5.17+ with kernel BTF and tracefs, libsystemd, SQLite, and the
documented capabilities. Arch Linux is the primary supported platform;
libalpm supplies optional package provenance.

For a complete installation on Arch Linux, use the AUR `electric-eye` package,
which installs the BPF object, systemd service, and configuration. To build the
BPF object yourself, use the project checkout and its pinned toolchain, then
pass `--ebpf-object /path/to/electric-eye-ebpf` to the daemon.

See [build and operations](https://github.com/jamesmcm/electric-eye/blob/main/docs/OPERATIONS.md)
and [toolchain requirements](https://github.com/jamesmcm/electric-eye/blob/main/docs/TOOLCHAIN.md).
The monitor observes and reports; it does not enforce policy.

License: MIT.
