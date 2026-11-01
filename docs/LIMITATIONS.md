# Known limitations

- `mmap` coverage reports writable shared mappings as `MMAP` intent; it does
  not track dirty-page writeback. Anonymous/private mappings are ignored.
- Sensitive read capture filters resolved absolute paths in the LPM trie,
  including successful relative opens. Home-directory prefixes are populated
  from `/etc/passwd` at startup; new accounts require a daemon restart.
- Path snapshots are bounded to 511 bytes and 80 dentry/mount steps. A missing
  VFS path hook leaves rename/unlink names marked lexical; incomplete walks
  remain unresolved. Failed opens retry at syscall exit and keep relative-name
  lexical fallbacks; pathless descriptors carry fd/dirfd/cwd and inode/device
  identity in the synthetic path. These fallbacks are visible in history.
- Write syscalls default to 5-second summaries, printing the top 32; these
  limits are configurable.
  Every aggregate is persisted and every original write is evaluated by rules.
- API clients default to a bounded worker pool, a 16 KiB request limit, and absolute
  request/write deadlines. Journal context is fetched asynchronously with a
  200 ms subprocess deadline and output limit; base incidents are saved first.
- MCP bounds request bytes while reading and imposes an absolute deadline on
  each incomplete frame. Idle sessions remain connected. Desktop files,
  known-host data and runtime metadata use bounded background workers; unavailable
  enrichment leaves conservative executable/namespace labels and active rules.
  Exemptions are tied to protected executable identities captured at startup;
  replacing/upgrading those executables requires a restart to refresh exemptions.
- Baseline suppression is intentionally conservative: it only suppresses
  already-known file paths, and novelty network alerts require at least five
  known destinations for that application by default.
- Quickshell UI, freeze/enforcement and NixOS packaging remain future work.
- Kernel metadata is bounded: argv/cwd/cgroup snapshots can be truncated or
  unavailable, and namespace-external parents may have no visible PID. Startup
  inventory is observational and cannot reconstruct activity before attachment.
- Socket hooks account for ordinary TCP/UDP application I/O; packet capture,
  DNS request decoding and mmap dirty-page accounting are separate capabilities.
  Event loss counters must be considered when interpreting incomplete histories.
- NixOS packaging and NixOS VM tests are deferred until the Arch release is
  stable.
