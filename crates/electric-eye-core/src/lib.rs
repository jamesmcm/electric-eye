pub mod event;

pub use event::{ExecEvent, ObservedEvent};

pub const LABEL_WIDTH: usize = 10;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample() -> ExecEvent {
        ExecEvent {
            pid: 4242,
            ppid: 400,
            uid: 1000,
            comm: "ls".into(),
            exe: PathBuf::from("/usr/bin/ls"),
        }
    }

    #[test]
    fn exec_display_is_label_padded() {
        let line = sample().to_string();
        assert_eq!(line, "EXEC      ls -> /usr/bin/ls");
        assert!(line.starts_with("EXEC"));
        assert_eq!(line.find("ls").unwrap(), LABEL_WIDTH);
    }

    #[test]
    fn observed_event_delegates_display() {
        let rendered = ObservedEvent::Exec(sample()).to_string();
        assert_eq!(rendered, "EXEC      ls -> /usr/bin/ls");
    }
}
