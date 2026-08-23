use std::fmt;
use std::path::PathBuf;

use crate::LABEL_WIDTH;

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: PathBuf,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub family: u32,
    pub addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
}

impl NetEvent {
    pub fn endpoint(&self) -> String {
        let port = if self.remote_port == 0 {
            self.local_port
        } else {
            self.remote_port
        };
        match self.family {
            AF_INET => format!(
                "{}.{}.{}.{}:{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3], port
            ),
            AF_INET6 => format!("[{}]:{}", std::net::Ipv6Addr::from(self.addr), port),
            _ => format!("(family {}):{}", self.family, port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub path: String,
    pub kind: FileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Write,
    Unlink,
}

impl FileKind {
    pub fn label(&self) -> &'static str {
        match self {
            FileKind::Write => "WRITE",
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
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub enum ObservedEvent {
    Exec(ExecEvent),
    Connect(NetEvent),
    Listen(NetEvent),
    FileWrite(FileEvent),
    FileUnlink(FileEvent),
    FileRename(RenameEvent),
    Traffic(TrafficSummary),
}

impl ObservedEvent {
    pub fn label(&self) -> &'static str {
        match self {
            ObservedEvent::Exec(event) => event.label(),
            ObservedEvent::Connect(_) => "CONNECT",
            ObservedEvent::Listen(_) => "LISTEN",
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
            ObservedEvent::Connect(event) => format!("{} -> {}", event.comm, event.endpoint()),
            ObservedEvent::Listen(event) => format!("{} -> {}", event.comm, event.endpoint()),
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
