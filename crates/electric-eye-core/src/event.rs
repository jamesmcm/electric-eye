use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use crate::LABEL_WIDTH;

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecEvent {
    pub pid: u32,
    /// Parent pid at the time the exec was observed.
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: PathBuf,
    /// `/proc/<pid>/stat` field 22. Together with `pid` this is the stable
    /// process identity: pids are reused, (pid, start_ticks) are not.
    pub start_ticks: u64,
}

impl ExecEvent {
    pub fn label(&self) -> &'static str {
        "EXEC"
    }
}

impl fmt::Display for ExecEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<width$}{} -> {}",
            self.label(),
            self.comm,
            self.exe.display(),
            width = LABEL_WIDTH
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExitEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
}

impl ExitEvent {
    pub fn label(&self) -> &'static str {
        "EXIT"
    }
}

impl fmt::Display for ExitEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<width$}{} (pid {})",
            self.label(),
            self.comm,
            self.pid,
            width = LABEL_WIDTH
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub family: u32,
    pub addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Set for ACCEPT events: the accepted file descriptor, used when the
    /// socket disappeared before userspace could resolve its endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
}

impl NetEvent {
    pub fn addr_string(&self) -> String {
        match self.family {
            AF_INET => format!(
                "{}.{}.{}.{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3]
            ),
            AF_INET6 => std::net::Ipv6Addr::from(self.addr).to_string(),
            _ => format!("(family {})", self.family),
        }
    }

    fn with_hostname(&self, endpoint: String) -> String {
        match &self.hostname {
            Some(hostname) if !hostname.is_empty() => format!("{endpoint} ({hostname})"),
            _ => endpoint,
        }
    }

    pub fn local_endpoint(&self) -> String {
        self.with_hostname(format!("{}:{}", self.addr_string(), self.local_port))
    }

    pub fn remote_endpoint(&self) -> String {
        self.with_hostname(format!("{}:{}", self.addr_string(), self.remote_port))
    }

    pub fn endpoint(&self) -> String {
        if self.remote_port == 0 {
            self.local_endpoint()
        } else {
            self.remote_endpoint()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub path: String,
    pub kind: FileKind,
    /// Present for actual write syscalls; None for open/create/truncate/unlink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Number of write syscalls collapsed into this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    Read,
    Open,
    Create,
    Truncate,
    Write,
    Mmap,
    Unlink,
}

impl FileKind {
    pub fn label(&self) -> &'static str {
        match self {
            FileKind::Read => "READ",
            FileKind::Open => "OPEN",
            FileKind::Create => "CREATE",
            FileKind::Truncate => "TRUNC",
            FileKind::Write => "WRITE",
            FileKind::Mmap => "MMAP",
            FileKind::Unlink => "UNLINK",
        }
    }
}

impl fmt::Display for FileEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<width$}{} -> {}",
            self.kind.label(),
            self.comm,
            self.path,
            width = LABEL_WIDTH
        )?;
        if let Some(bytes) = self.bytes {
            if let Some(count) = self.count.filter(|count| *count > 1) {
                write!(f, " ({count} writes, {})", humanize_bytes(bytes))?;
            } else {
                write!(f, " ({})", humanize_bytes(bytes))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenameEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub from_path: String,
    pub to_path: String,
}

impl fmt::Display for RenameEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<width$}{} -> {} -> {}",
            "RENAME",
            self.comm,
            self.from_path,
            self.to_path,
            width = LABEL_WIDTH
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrafficSummary {
    pub pid: u32,
    pub comm: String,
    pub sent: u64,
    pub recv: u64,
}

impl TrafficSummary {
    pub fn label(&self) -> &'static str {
        "TRAFFIC"
    }

    pub fn total(&self) -> u64 {
        self.sent + self.recv
    }
}

impl fmt::Display for TrafficSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<width$}{} sent={} recv={}",
            self.label(),
            self.comm,
            humanize_bytes(self.sent),
            humanize_bytes(self.recv),
            width = LABEL_WIDTH
        )
    }
}

pub fn humanize_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ObservedEvent {
    Exec(ExecEvent),
    Exit(ExitEvent),
    Connect(NetEvent),
    Accept(NetEvent),
    Listen(NetEvent),
    FileRead(FileEvent),
    FileOpen(FileEvent),
    FileWrite(FileEvent),
    FileUnlink(FileEvent),
    FileRename(RenameEvent),
    Traffic(TrafficSummary),
}

impl ObservedEvent {
    pub fn label(&self) -> &'static str {
        match self {
            ObservedEvent::Exec(event) => event.label(),
            ObservedEvent::Exit(event) => event.label(),
            ObservedEvent::Connect(_) => "CONNECT",
            ObservedEvent::Accept(_) => "ACCEPT",
            ObservedEvent::Listen(_) => "LISTEN",
            ObservedEvent::FileRead(event) => event.kind.label(),
            ObservedEvent::FileOpen(event) => event.kind.label(),
            ObservedEvent::FileWrite(event) => event.kind.label(),
            ObservedEvent::FileUnlink(event) => event.kind.label(),
            ObservedEvent::FileRename(_) => "RENAME",
            ObservedEvent::Traffic(summary) => summary.label(),
        }
    }
}

impl fmt::Display for ObservedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = match self {
            ObservedEvent::Exec(event) => return write!(f, "{}", event),
            ObservedEvent::Exit(event) => return write!(f, "{}", event),
            ObservedEvent::Connect(event) => format!("{} -> {}", event.comm, event.endpoint()),
            ObservedEvent::Accept(event) => match (event.family, event.fd) {
                (0, Some(fd)) => format!("{} -> fd {fd}", event.comm),
                _ if event.local_port == 0 => {
                    format!("{} -> {}", event.comm, event.remote_endpoint())
                }
                _ => format!(
                    "{} -> {} (local :{})",
                    event.comm,
                    event.remote_endpoint(),
                    event.local_port
                ),
            },
            ObservedEvent::Listen(event) => format!("{} -> {}", event.comm, event.endpoint()),
            ObservedEvent::FileRead(event) => return write!(f, "{}", event),
            ObservedEvent::FileOpen(event) => return write!(f, "{}", event),
            ObservedEvent::FileWrite(event) => return write!(f, "{}", event),
            ObservedEvent::FileUnlink(event) => return write!(f, "{}", event),
            ObservedEvent::FileRename(event) => return write!(f, "{}", event),
            ObservedEvent::Traffic(summary) => {
                format!(
                    "{} sent={} recv={}",
                    summary.comm,
                    humanize_bytes(summary.sent),
                    humanize_bytes(summary.recv)
                )
            }
        };
        write!(f, "{:<width$}{}", self.label(), body, width = LABEL_WIDTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net_event(local_port: u16, remote_port: u16) -> NetEvent {
        NetEvent {
            pid: 7,
            uid: 1000,
            comm: "curl".into(),
            family: AF_INET,
            addr: [140, 82, 121, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            local_port,
            remote_port,
            hostname: None,
            fd: None,
        }
    }

    #[test]
    fn connect_renders_remote_endpoint() {
        let event = ObservedEvent::Connect(net_event(51000, 443)).to_string();
        assert_eq!(event, "CONNECT   curl -> 140.82.121.3:443");
    }

    #[test]
    fn listen_renders_local_endpoint() {
        let event = ObservedEvent::Listen(net_event(8000, 0)).to_string();
        assert_eq!(event, "LISTEN    curl -> 140.82.121.3:8000");
    }

    #[test]
    fn accept_renders_remote_and_local_ports() {
        let event = ObservedEvent::Accept(net_event(8000, 51000)).to_string();
        assert_eq!(event, "ACCEPT    curl -> 140.82.121.3:51000 (local :8000)");
    }

    #[test]
    fn unresolved_accept_falls_back_to_fd() {
        let mut net = net_event(0, 0);
        net.family = 0;
        net.addr = [0; 16];
        net.fd = Some(7);
        let event = ObservedEvent::Accept(net).to_string();
        assert_eq!(event, "ACCEPT    curl -> fd 7");
    }

    #[test]
    fn file_event_kinds_render_distinctly() {
        let make = |kind, bytes, count| FileEvent {
            pid: 1,
            uid: 1000,
            comm: "test".into(),
            path: "/tmp/x".into(),
            kind,
            bytes,
            count,
        };
        assert_eq!(
            make(FileKind::Open, None, None).to_string(),
            "OPEN      test -> /tmp/x"
        );
        assert_eq!(
            make(FileKind::Create, None, None).to_string(),
            "CREATE    test -> /tmp/x"
        );
        assert_eq!(
            make(FileKind::Truncate, None, None).to_string(),
            "TRUNC     test -> /tmp/x"
        );
        assert_eq!(
            make(FileKind::Write, Some(2048), Some(1)).to_string(),
            "WRITE     test -> /tmp/x (2.0 KiB)"
        );
        assert_eq!(
            make(FileKind::Write, Some(2048), Some(3)).to_string(),
            "WRITE     test -> /tmp/x (3 writes, 2.0 KiB)"
        );
    }

    #[test]
    fn exit_includes_pid() {
        let event = ObservedEvent::Exit(ExitEvent {
            pid: 42,
            uid: 1000,
            comm: "sleep".into(),
        })
        .to_string();
        assert_eq!(event, "EXIT      sleep (pid 42)");
    }

    #[test]
    fn open_is_tagged_separately_from_write() {
        let event = FileEvent {
            pid: 1,
            uid: 0,
            comm: "touch".into(),
            path: "/tmp/x".into(),
            kind: FileKind::Create,
            bytes: None,
            count: None,
        };
        let value = serde_json::to_value(ObservedEvent::FileOpen(event)).unwrap();
        assert_eq!(value["event"], "file_open");
        assert_eq!(value["kind"], "create");
    }

    #[test]
    fn observed_events_serialize_with_a_tag() {
        let value = serde_json::to_value(ObservedEvent::FileUnlink(FileEvent {
            pid: 1,
            uid: 0,
            comm: "rm".into(),
            path: "/tmp/x".into(),
            kind: FileKind::Unlink,
            bytes: None,
            count: None,
        }))
        .unwrap();
        assert_eq!(value["event"], "file_unlink");
        assert_eq!(value["kind"], "unlink");
        assert_eq!(value["path"], "/tmp/x");
    }
}
