use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use electric_eye_core::ObservedEvent;
use serde::Serialize;
use serde_json::{Value, json};

use crate::store::StoreClient;

pub const DEFAULT_SOCKET: &str = "/run/electric-eye/electric-eye.sock";
const ACTIVITY_LIMIT: usize = 2048;
const CLIENT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ns: u64,
    pub boot_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub ts_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_result: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_resolution: Option<String>,
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
    capture_loss: Vec<u64>,
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
            capture_loss: vec![],
        }
    }

    pub fn record_incident(&mut self, incident: Value) {
        if let Some(id) = incident["id"].as_str()
            && let Some(existing) = self
                .incidents
                .iter_mut()
                .find(|item| item["id"].as_str() == Some(id))
        {
            *existing = incident;
            return;
        }
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

    pub fn set_capture_loss(&mut self, counts: Vec<u64>) {
        self.capture_loss = counts;
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
        json!({
            "daemon": "electric-eyed",
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "kernel": crate::probe::kernel_release(),
            "uptime_secs": self.started.elapsed().as_secs(),
            "attached_probes": self.attached,
            "skipped_probes": self.skipped,
            "events_total": self.events_total,
            "activity_buffered": self.activity.len(),
            "capture_loss": self.capture_loss,
        })
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

const API_WORKERS: usize = 4;
const MAX_REQUEST_BYTES: usize = 16 * 1024;

pub struct ApiServer {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl ApiServer {
    pub fn start(socket: SocketGuard, state: Arc<Mutex<SharedState>>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let join = std::thread::Builder::new()
            .name("electric-eye-api".into())
            .spawn(move || {
                let mut workers = Vec::new();
                let mut queues = Vec::new();
                for _ in 0..API_WORKERS {
                    let (tx, rx) = sync_channel::<UnixStream>(1);
                    let state = Arc::clone(&state);
                    workers.push(std::thread::spawn(move || {
                        while let Ok(stream) = rx.recv() {
                            if let Err(err) = handle_client(stream, &state) {
                                log::debug!("API request rejected: {err}");
                            }
                        }
                    }));
                    queues.push(tx);
                }
                let mut next = 0;
                while !stopping.load(Ordering::Relaxed) {
                    for _ in 0..16 {
                        match socket.listener.accept() {
                            Ok((mut stream, _)) => {
                                for _ in 0..API_WORKERS {
                                    let index = next;
                                    next = (next + 1) % API_WORKERS;
                                    match queues[index].try_send(stream) {
                                        Ok(()) => break,
                                        Err(TrySendError::Full(s)) => {
                                            stream = s;
                                        }
                                        Err(TrySendError::Disconnected(_)) => break,
                                    }
                                }
                            }
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                            Err(err) => {
                                log::warn!("API accept: {err}");
                                break;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                drop(queues);
                for worker in workers {
                    let _ = worker.join();
                }
                drop(socket);
            })?;
        Ok(Self {
            stop,
            join: Some(join),
        })
    }
}
impl Drop for ApiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "API request deadline exceeded"))
}
fn read_request(stream: &mut UnixStream) -> io::Result<String> {
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete API request",
            ));
        }
        let end = buf[..n].iter().position(|b| *b == b'\n');
        let count = end.unwrap_or(n);
        if line.len() + count > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "API request too large",
            ));
        }
        line.extend_from_slice(&buf[..count]);
        if end.is_some() {
            return String::from_utf8(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
    }
}
fn handle_client(mut stream: UnixStream, state: &Arc<Mutex<SharedState>>) -> io::Result<()> {
    let line = read_request(&mut stream)?;
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
        "status" => {
            let mut value = state.lock().unwrap().status_value();
            value["store"] = store
                .as_ref()
                .map(StoreClient::status_value)
                .unwrap_or(Value::Null);
            value
        }
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

    let mut response = serde_json::to_vec(&response)?;
    response.push(b'\n');
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let mut written = 0;
    while written < response.len() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let n = stream.write(&response[written..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "API client closed",
            ));
        }
        written += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use electric_eye_core::{ExecEvent, FileEvent, FileKind};
    use std::path::PathBuf;

    fn entry(pid: u32, comm: &str) -> ActivityEntry {
        ActivityEntry {
            ts_ms: now_ms(),
            syscall_result: None,
            process: None,
            path_resolution: None,
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
            syscall_result: None,
            process: None,
            path_resolution: None,
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

#[cfg(test)]
mod request_regressions {
    use super::*;
    #[test]
    fn rejects_oversized_lines() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ = client.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1]);
        });
        assert_eq!(
            read_request(&mut server).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        writer.join().unwrap();
    }
    #[test]
    fn deadline_is_absolute_even_when_client_keeps_sending() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..15 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let start = Instant::now();
        assert!(read_request(&mut server).is_err());
        assert!(start.elapsed() < Duration::from_millis(750));
        drop(server);
        writer.join().unwrap();
    }
    #[test]
    fn slow_client_does_not_block_another_request_or_capture_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("api.sock");
        let socket = bind_socket(&path).unwrap();
        let state = Arc::new(Mutex::new(SharedState::new()));
        let server = ApiServer::start(socket, Arc::clone(&state)).unwrap();
        let _slow = UnixStream::connect(&path).unwrap();
        let start = Instant::now();
        state.lock().unwrap().set_capture_loss(vec![1]);
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        client.write_all(b"{\"op\":\"status\"}\n").unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap()["capture_loss"][0],
            1
        );
        assert!(start.elapsed() < Duration::from_millis(450));
        drop(server);
    }
}
