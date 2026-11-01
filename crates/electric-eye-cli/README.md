# electric-eye-cli

The read-only CLI, terminal UI, and MCP stdio bridge for
[Electric Eye](https://github.com/jamesmcm/electric-eye), a Linux activity monitor.

```bash
cargo install --locked electric-eye-cli
electric-eye status
electric-eye tui
```

The installed binary is **electric-eye**. It requires a running `electric-eyed`
daemon and permission to access its Unix socket. On Arch Linux, the AUR
`electric-eye` package supplies the daemon, BPF object, systemd service, and
configuration. The Cargo CLI package supplies the client only.

See [installation and operations](https://github.com/jamesmcm/electric-eye/blob/main/docs/OPERATIONS.md)
for setup, group membership, and system requirements.

License: MIT.
