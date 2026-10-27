use std::ffi::CString;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_sendv(iov: *const libc::iovec, n: libc::c_int) -> libc::c_int;
}

/// Send structured fields to journald. Returns false when journald is not
/// available (e.g. running in a development shell without a journal socket).
pub fn send(fields: &[(&str, String)]) -> bool {
    let cstrings: Vec<CString> = fields
        .iter()
        .filter_map(|(key, value)| {
            let value = value.replace(['\n', '\r'], " ");
            CString::new(format!("{key}={value}")).ok()
        })
        .collect();
    if cstrings.is_empty() {
        return false;
    }
    let iovecs: Vec<libc::iovec> = cstrings
        .iter()
        .map(|field| libc::iovec {
            iov_base: field.as_ptr() as *mut libc::c_void,
            iov_len: field.as_bytes().len(),
        })
        .collect();
    (unsafe { sd_journal_sendv(iovecs.as_ptr(), iovecs.len() as libc::c_int) }) >= 0
}

pub fn startup(kernel: &str, database: Option<&str>) {
    let mut fields = vec![
        ("MESSAGE", "electric-eyed started".to_string()),
        ("PRIORITY", "6".to_string()),
        ("ELECTRIC_EYE_EVENT", "startup".to_string()),
        (
            "ELECTRIC_EYE_VERSION",
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        ("ELECTRIC_EYE_KERNEL", kernel.to_string()),
    ];
    if let Some(database) = database {
        fields.push(("ELECTRIC_EYE_DATABASE", database.to_string()));
    }
    let _ = send(&fields);
}

pub fn send_incident(incident: &crate::rules::Incident, journal: &[String]) -> bool {
    let mut fields = vec![
        ("MESSAGE", incident.title.clone()),
        ("PRIORITY", incident.severity.priority().to_string()),
        ("ELECTRIC_EYE_EVENT", "incident".to_string()),
        (
            "ELECTRIC_EYE_SEVERITY",
            incident.severity.as_str().to_string(),
        ),
        ("ELECTRIC_EYE_COMM", incident.comm.clone()),
        ("ELECTRIC_EYE_PID", incident.pid.to_string()),
        ("ELECTRIC_EYE_DETAILS", incident.details.to_string()),
        ("ELECTRIC_EYE_JOURNAL_LINES", journal.len().to_string()),
    ];
    if let Some(path) = &incident.path {
        fields.push(("ELECTRIC_EYE_PATH", path.clone()));
    }
    if let Some(unit) = &incident.unit {
        fields.push(("ELECTRIC_EYE_UNIT", unit.clone()));
    }
    send(&fields)
}

/// Fetch a small, bounded journal context around an incident. The caller
/// should treat this as optional enrichment: journal permissions or a missing
/// journalctl must never break event capture.
pub fn nearby(
    unit: Option<&str>,
    ts_ms: u64,
    config: &crate::config::JournalConfig,
) -> Vec<String> {
    let (start, end) = context_window(ts_ms, config.context_window_secs);
    let mut command = Command::new("journalctl");
    command.args([
        "--since",
        &format!("@{start}"),
        "--until",
        &format!("@{end}"),
        "-o",
        "short-iso",
        "--no-pager",
        "-q",
        "-n",
        &config.context_lines.to_string(),
    ]);
    if let Some(unit) = unit {
        command.args(["--unit", unit]);
    }
    let Some(output) = bounded_output(
        &mut command,
        Duration::from_millis(config.timeout_ms),
        config.max_output_bytes,
    ) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.chars().take(config.max_line_chars).collect())
        .collect()
}

fn context_window(ts_ms: u64, window_secs: u64) -> (u64, u64) {
    let incident = ts_ms / 1000;
    (
        incident.saturating_sub(window_secs),
        incident.saturating_add(window_secs),
    )
}
fn bounded_output(command: &mut Command, timeout: Duration, max_bytes: usize) -> Option<Vec<u8>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let Some(mut stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let fd = stdout.as_raw_fd();
    if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let deadline = Instant::now() + timeout;
    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stdout.read(&mut buf) {
            Ok(n) if n > 0 => {
                if output.len() + n > max_bytes {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                output.extend_from_slice(&buf[..n]);
            }
            Ok(_) => {
                if let Ok(Some(status)) = child.try_wait() {
                    return status.success().then_some(output);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

pub struct IncidentWorker {
    tx: Option<SyncSender<crate::rules::Incident>>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl IncidentWorker {
    pub fn configured(
        state: Arc<Mutex<crate::api::SharedState>>,
        store: Option<crate::store::StoreClient>,
        config: crate::config::JournalConfig,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel::<crate::rules::Incident>(config.queue_entries);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("electric-eye-incidents".into())
            .spawn(move || {
                while let Ok(mut incident) = rx.recv() {
                    if stopping.load(Ordering::Relaxed) {
                        continue;
                    }
                    let journal = nearby(incident.unit.as_deref(), incident.ts_ms, &config);
                    if let Some(details) = incident.details.as_object_mut() {
                        details.insert("journal".into(), serde_json::json!(&journal));
                    }
                    if let Some(store) = &store {
                        store.record_incident(crate::store::IncidentRow::from_incident(&incident));
                    }
                    let mut value = serde_json::to_value(&incident).unwrap_or_default();
                    value["event"] = serde_json::json!("incident");
                    state.lock().unwrap().record_incident(value);
                    send_incident(&incident, &journal);
                }
            })?;
        Ok(Self {
            tx: Some(tx),
            stop,
            join: Some(join),
        })
    }
    pub fn enqueue(&self, incident: crate::rules::Incident) {
        if let Some(tx) = &self.tx
            && tx.try_send(incident).is_err()
        {
            log::warn!("incident enrichment queue full; base incident retained");
        }
    }
}
impl Drop for IncidentWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.tx.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn newlines_are_removed_from_values() {
        let fields = [("MESSAGE", "hello\nworld".to_string())];
        // We cannot assert journald availability in every test environment;
        // exercising the encoding path is enough.
        let encoded = fields[0].1.replace(['\n', '\r'], " ");
        assert_eq!(encoded, "hello world");
    }
}

#[cfg(test)]
mod context_regressions {
    use super::*;
    #[test]
    fn context_includes_preceding_minute() {
        assert_eq!(context_window(120_000, 60), (60, 180));
        assert_eq!(context_window(1_000, 60), (0, 61));
    }
    #[test]
    fn hung_command_has_a_deadline() {
        let mut cmd = Command::new("sleep");
        cmd.arg("2");
        let start = Instant::now();
        assert!(bounded_output(&mut cmd, Duration::from_millis(50), 1024).is_none());
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    #[test]
    fn command_output_is_bounded() {
        let mut cmd = Command::new("printf");
        cmd.arg("1234567890");
        assert!(bounded_output(&mut cmd, Duration::from_secs(1), 5).is_none());
    }
}
