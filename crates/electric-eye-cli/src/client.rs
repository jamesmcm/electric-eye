use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

pub const DEFAULT_SOCKET: &str = "/run/electric-eye/electric-eye.sock";
pub const DEFAULT_MCP_SOCKET: &str = "/run/electric-eye/mcp.sock";
const TIMEOUT: Duration = Duration::from_secs(2);

pub fn request(socket: &Path, request: &Value) -> anyhow::Result<Value> {
    request_with_timeout(socket, request, TIMEOUT)
}

pub fn request_with_timeout(
    socket: &Path,
    request: &Value,
    timeout: Duration,
) -> anyhow::Result<Value> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(request.to_string().as_bytes())?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    serde_json::from_str(response.trim())
        .map_err(|err| anyhow::anyhow!("daemon returned invalid JSON: {err}"))
}

pub fn socket_from_env() -> PathBuf {
    std::env::var_os("ELECTRIC_EYE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

pub fn mcp_socket_from_env() -> PathBuf {
    std::env::var_os("ELECTRIC_EYE_MCP_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MCP_SOCKET))
}
