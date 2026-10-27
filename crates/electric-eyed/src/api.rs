use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use electric_eye_core::ObservedEvent;
use serde::Serialize;
use serde_json::{Value, json};

use crate::store::StoreClient;

pub const DEFAULT_SOCKET: &str = "/run/electric-eye/electric-eye.sock";
const ACTIVITY_LIMIT: usize = 2048;
const CLIENT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub ts_ms: u64,
    pub event: ObservedEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AppStat {
    pub events: u64,
    pub sent: u64,
    pub recv: u64,
}

pub struct SharedState {
    started: Instant,
    attached: Vec<String>,
    skipped: Vec<String>,
    events_total: u64,
    activity: VecDeque<ActivityEntry>,
    apps: HashMap<String, AppStat>,
    incidents: VecDeque<Value>,
    store: Option<StoreClient>,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            attached: Vec::new(),
            skipped: Vec::new(),
            events_total: 0,
            activity: VecDeque::new(),
            apps: HashMap::new(),
            incidents: VecDeque::new(),
            store: None,
        }
    }

    pub fn record_incident(&mut self, incident: Value) {
        self.incidents.push_back(incident);
        while self.incidents.len() > 200 {
            self.incidents.pop_front();
        }
    }

    pub fn recent_incidents(&self, limit: usize) -> Vec<Value> {
        self.incidents.iter().rev().take(limit).cloned().collect()
    }

    pub fn set_store(&mut self, store: Option<StoreClient>) {
        self.store = store;
    }

    pub fn store_client(&self) -> Option<StoreClient> {
        self.store.clone()
    }

    pub fn set_probes(&mut self, attached: Vec<String>, skipped: Vec<String>) {
        self.attached = attached;
        self.skipped = skipped;
    }

    pub fn record(&mut self, entry: ActivityEntry) {
        self.events_total += 1;
        let comm = event_comm(&entry.event);
        let stats = self.apps.entry(comm).or_default();
        match &entry.event {
            ObservedEvent::Traffic(summary) => {
                stats.sent += summary.sent;
                stats.recv += summary.recv;
            }
            _ => stats.events += 1,
        }

        self.activity.push_back(entry);
        while self.activity.len() > ACTIVITY_LIMIT {
            self.activity.pop_front();
        }
    }

    pub fn status_value(&self) -> Value {
        let mut value = json!({
            "daemon": "electric-eyed",
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "kernel": crate::probe::kernel_release(),
            "uptime_secs": self.started.elapsed().as_secs(),
            "attached_probes": self.attached,
            "skipped_probes": self.skipped,
            "events_total": self.events_total,
            "activity_buffered": self.activity.len(),
        });
        value["store"] = self
            .store
            .as_ref()
            .map(StoreClient::status_value)
            .unwrap_or(Value::Null);
        value
    }

    pub fn activity_value(&self, limit: usize) -> Value {
        let entries: Vec<&ActivityEntry> = self.activity.iter().rev().take(limit).collect();
        json!({ "activity": entries })
    }

    pub fn apps_value(&self) -> Value {
        let mut apps: Vec<(&String, &AppStat)> = self.apps.iter().collect();
        apps.sort_by_key(|a| std::cmp::Reverse(a.1.events + a.1.sent + a.1.recv));
        let apps: Vec<Value> = apps
            .into_iter()
            .map(|(comm, stat)| {
                json!({
                    "comm": comm,
                    "events": stat.events,
                    "sent": stat.sent,
                    "recv": stat.recv,
                })
            })
            .collect();
        json!({ "apps": apps })
    }
}

fn event_comm(event: &ObservedEvent) -> String {
    match event {
        ObservedEvent::Exec(event) => event.comm.clone(),
        ObservedEvent::Exit(event) => event.comm.clone(),
        ObservedEvent::Connect(event)
        | ObservedEvent::Accept(event)
        | ObservedEvent::Listen(event) => event.comm.clone(),
        ObservedEvent::FileRead(event)
        | ObservedEvent::FileOpen(event)
        | ObservedEvent::FileWrite(event)
        | ObservedEvent::FileUnlink(event) => event.comm.clone(),
        ObservedEvent::FileRename(event) => event.comm.clone(),
        ObservedEvent::Traffic(summary) => summary.comm.clone(),
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub struct SocketGuard {
    path: PathBuf,
    listener: UnixListener,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn bind_socket(path: &Path) -> io::Result<SocketGuard> {
    if let Some(parent) = path.parent() {
        let existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        if !existed {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        }
    }
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "another electric-eyed is already listening on {}",
                        path.display()
                    ),
                ));
            }
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(SocketGuard {
        path: path.to_path_buf(),
        listener,
    })
}

pub fn serve_pending(socket: &SocketGuard, state: &Arc<Mutex<SharedState>>) {
    loop {
        match socket.listener.accept() {
            Ok((stream, _addr)) => {
                if let Err(err) = handle_client(stream, state) {
                    log::warn!("api client failed: {err}");
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => {
                log::warn!("api accept failed: {err}");
                break;
            }
        }
    }
}

fn handle_client(stream: UnixStream, state: &Arc<Mutex<SharedState>>) -> io::Result<()> {
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let request: Value = serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({}));
    let op = request["op"].as_str().unwrap_or_default();
    let limit = request["limit"]
        .as_u64()
        .unwrap_or(100)
        .clamp(1, ACTIVITY_LIMIT as u64) as usize;

    let store = state.lock().unwrap().store_client();
    let query = |result: anyhow::Result<Value>| {
        result.unwrap_or_else(|err| json!({ "error": format!("{err:#}") }))
    };
    let no_store = || json!({ "error": "persistence disabled (--no-db or database unavailable)" });

    let response = match op {
        "status" => state.lock().unwrap().status_value(),
        "activity" => {
            let mut value = state.lock().unwrap().activity_value(limit);
            if let Some(store) = &store
                && let Ok(persisted) = store.recent_activities(20)
            {
                value["persisted_activities"] = persisted["activities"].clone();
            }
            value
        }
        "apps" => state.lock().unwrap().apps_value(),
        "incidents" => {
            let recent = state.lock().unwrap().recent_incidents(limit);
            match &store {
                Some(store) => {
                    let mut value = query(store.incidents(limit));
                    value["recent"] = json!(recent);
                    value
                }
                None => json!({ "incidents": recent }),
            }
        }
        "file" => {
            let path = request["path"].as_str().unwrap_or_default();
            if path.is_empty() {
                json!({ "error": "file requires a path" })
            } else {
                match &store {
                    Some(store) => query(store.file_activities(path, limit)),
                    None => no_store(),
                }
            }
        }
        "app" => {
            let app = request["app"].as_str().unwrap_or_default();
            if app.is_empty() {
                json!({ "error": "app requires an application name" })
            } else {
                match &store {
                    Some(store) => query(store.app_activities(app, limit)),
                    None => no_store(),
                }
            }
        }
        "network" => match &store {
            Some(store) => query(store.network_activities(limit)),
            None => no_store(),
        },
        "why" => {
            let path = request["path"].as_str().unwrap_or_default();
            if path.is_empty() {
                json!({ "error": "why requires a path" })
            } else {
                match &store {
                    Some(store) => query(store.why(path, limit)),
                    None => no_store(),
                }
            }
        }
        "" => json!({ "error": "missing op" }),
        other => json!({ "error": format!("unknown op {other}") }),
    };

    serde_json::to_writer(&mut writer, &response)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use electric_eye_core::{ExecEvent, FileEvent, FileKind};
    use std::path::PathBuf;

    fn entry(pid: u32, comm: &str) -> ActivityEntry {
        ActivityEntry {
            ts_ms: now_ms(),
            event: ObservedEvent::Exec(ExecEvent {
                pid,
                ppid: 1,
                uid: 1000,
                comm: comm.into(),
                exe: PathBuf::from("/usr/bin/test"),
                start_ticks: 1,
            }),
            unit: None,
            nix: None,
            parent: Some("bash".into()),
            exe: None,
        }
    }

    #[test]
    fn records_and_limits_activity() {
        let mut state = SharedState::new();
        for i in 0..(ACTIVITY_LIMIT + 10) {
            state.record(entry(i as u32, "test"));
        }
        assert_eq!(state.activity.len(), ACTIVITY_LIMIT);
        assert_eq!(state.events_total, (ACTIVITY_LIMIT + 10) as u64);
        let value = state.activity_value(5);
        assert_eq!(value["activity"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn aggregates_apps_and_traffic() {
        let mut state = SharedState::new();
        state.record(entry(1, "curl"));
        state.record(ActivityEntry {
            ts_ms: now_ms(),
            event: ObservedEvent::FileUnlink(FileEvent {
                pid: 1,
                uid: 1000,
                comm: "curl".into(),
                path: "/tmp/x".into(),
                kind: FileKind::Unlink,
                bytes: None,
                count: None,
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: None,
        });
        let value = state.apps_value();
        assert_eq!(value["apps"][0]["comm"], "curl");
        assert_eq!(value["apps"][0]["events"], 2);
    }
}
