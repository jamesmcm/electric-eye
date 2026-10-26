use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

const SOCKET_PATH: &str = "/run/electric-eye/electric-eye.sock";
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status,
    Activity,
    Apps,
    Incidents,
    File(String),
    App(String),
    Network,
    Why(String),
}

impl Command {
    pub fn parse(args: &[String]) -> Option<Command> {
        match args.first().map(String::as_str) {
            Some("status") => Some(Command::Status),
            Some("activity") => Some(Command::Activity),
            Some("apps") => Some(Command::Apps),
            Some("incidents") => Some(Command::Incidents),
            Some("file") => args.get(1).map(|path| Command::File(path.clone())),
            Some("app") => args.get(1).map(|app| Command::App(app.clone())),
            Some("network") => Some(Command::Network),
            Some("why") => args.get(1).map(|path| Command::Why(path.clone())),
            _ => None,
        }
    }

    pub fn request(&self) -> String {
        let value = match self {
            Command::Status => serde_json::json!({ "op": "status" }),
            Command::Activity => serde_json::json!({ "op": "activity", "limit": 100 }),
            Command::Apps => serde_json::json!({ "op": "apps" }),
            Command::Incidents => serde_json::json!({ "op": "incidents" }),
            Command::File(path) => serde_json::json!({ "op": "file", "path": path }),
            Command::App(app) => serde_json::json!({ "op": "app", "app": app }),
            Command::Network => serde_json::json!({ "op": "network" }),
            Command::Why(path) => serde_json::json!({ "op": "why", "path": path }),
        };
        value.to_string()
    }
}

fn socket_path(args: &mut Vec<String>) -> PathBuf {
    let mut path = std::env::var_os("ELECTRIC_EYE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(SOCKET_PATH));
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--socket" {
            if index + 1 < args.len() {
                path = PathBuf::from(args.remove(index + 1));
            }
            args.remove(index);
        } else {
            index += 1;
        }
    }
    path
}

fn connect(path: &PathBuf) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    Ok(stream)
}

fn run(command: &Command, socket: &PathBuf) -> anyhow::Result<i32> {
    match connect(socket) {
        Ok(mut stream) => {
            stream.write_all(command.request().as_bytes())?;
            stream.write_all(b"\n")?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            match serde_json::from_str::<serde_json::Value>(response.trim()) {
                Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
                Err(_) => println!("{}", response.trim_end()),
            }
            Ok(0)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("electric-eyed is not running");
            eprintln!("expected daemon socket at {}", socket.display());
            eprintln!(
                "start it with: sudo electric-eyed --stdout (or the electric-eye.service unit)"
            );
            Ok(1)
        }
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
            eprintln!(
                "electric-eyed socket exists but nothing is listening at {}",
                socket.display()
            );
            Ok(1)
        }
        Err(err) => {
            eprintln!("failed to reach {}: {err}", socket.display());
            Ok(1)
        }
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let socket = socket_path(&mut args);

    let Some(command) = Command::parse(&args) else {
        eprintln!("electric-eye - query the electric-eyed monitor");
        eprintln!();
        eprintln!("USAGE: electric-eye [--socket <path>] <COMMAND>");
        eprintln!();
        eprintln!("COMMANDS:");
        for cmd in [
            "status               show daemon status",
            "activity             show recent activity",
            "apps                 list known applications",
            "app <name>           show recent activity for an application",
            "file <path>          show activity for a file",
            "network              show recent network activity",
            "why <path>           show who touched a file",
            "incidents            list recorded incidents",
        ] {
            eprintln!("  {cmd}");
        }
        return ExitCode::from(2);
    };

    match run(&command, &socket) {
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
    fn parses_path_and_app_commands() {
        assert_eq!(
            Command::parse(&args(&["file", "/tmp/x"])),
            Some(Command::File("/tmp/x".into()))
        );
        assert_eq!(
            Command::parse(&args(&["app", "firefox"])),
            Some(Command::App("firefox".into()))
        );
        assert_eq!(
            Command::parse(&args(&["why", "/tmp/x"])),
            Some(Command::Why("/tmp/x".into()))
        );
        assert_eq!(Command::parse(&args(&["network"])), Some(Command::Network));
    }

    #[test]
    fn rejects_unknown_commands() {
        assert_eq!(Command::parse(&args(&[])), None);
        assert_eq!(Command::parse(&args(&["frobnicate"])), None);
        assert_eq!(Command::parse(&args(&["file"])), None);
    }

    #[test]
    fn extracts_socket_override() {
        let mut items = args(&["--socket", "/tmp/ee.sock", "status"]);
        assert_eq!(socket_path(&mut items), PathBuf::from("/tmp/ee.sock"));
        assert_eq!(items, args(&["status"]));
    }
}
