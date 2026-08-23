use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

const SOCKET_PATH: &str = "/run/electric-eye/electric-eye.sock";
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Status,
    Activity,
    Apps,
    Incidents,
}

impl Command {
    pub fn parse(args: &[String]) -> Option<Command> {
        match args.first().map(String::as_str) {
            Some("status") => Some(Command::Status),
            Some("activity") => Some(Command::Activity),
            Some("apps") => Some(Command::Apps),
            Some("incidents") => Some(Command::Incidents),
            _ => None,
        }
    }

    pub fn request(self) -> &'static str {
        match self {
            Command::Status => r#"{"op":"status"}"#,
            Command::Activity => r#"{"op":"activity"}"#,
            Command::Apps => r#"{"op":"apps"}"#,
            Command::Incidents => r#"{"op":"incidents"}"#,
        }
    }
}

fn connect() -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(SOCKET_PATH)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    Ok(stream)
}

fn run(command: Command) -> anyhow::Result<i32> {
    match connect() {
        Ok(mut stream) => {
            stream.write_all(command.request().as_bytes())?;
            stream.write_all(b"\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            println!("{}", response.trim_end());
            Ok(0)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("electric-eyed is not running");
            eprintln!("expected daemon socket at {SOCKET_PATH}");
            eprintln!(
                "start it with: sudo electric-eyed --stdout (or the electric-eye.service unit)"
            );
            Ok(1)
        }
        Err(err) => {
            eprintln!("failed to reach {SOCKET_PATH}: {err}");
            Ok(1)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some(command) = Command::parse(&args) else {
        eprintln!("electric-eye - query the electric-eyed monitor");
        eprintln!();
        eprintln!("USAGE: electric-eye <COMMAND>");
        eprintln!();
        eprintln!("COMMANDS:");
        for cmd in [
            "status      show daemon status",
            "activity    show recent activity",
            "apps        list known applications",
            "incidents   list recorded incidents",
        ] {
            eprintln!("  {cmd}");
        }
        return ExitCode::from(2);
    };

    match run(command) {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_known_commands() {
        assert_eq!(Command::parse(&args(&["status"])), Some(Command::Status));
        assert_eq!(
            Command::parse(&args(&["activity"])),
            Some(Command::Activity)
        );
        assert_eq!(Command::parse(&args(&["apps"])), Some(Command::Apps));
        assert_eq!(
            Command::parse(&args(&["incidents"])),
            Some(Command::Incidents)
        );
    }

    #[test]
    fn rejects_unknown_commands() {
        assert_eq!(Command::parse(&args(&[])), None);
        assert_eq!(Command::parse(&args(&["frobnicate"])), None);
    }
}
