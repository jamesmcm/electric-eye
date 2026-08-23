use std::fmt;
use std::path::PathBuf;

use crate::LABEL_WIDTH;

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

#[derive(Debug, Clone)]
pub enum ObservedEvent {
    Exec(ExecEvent),
}

impl fmt::Display for ObservedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservedEvent::Exec(event) => write!(f, "{}", event),
        }
    }
}
