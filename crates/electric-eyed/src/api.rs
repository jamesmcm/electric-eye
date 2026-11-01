use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use electric_eye_core::ObservedEvent;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::store::StoreClient;

pub const DEFAULT_SOCKET: &str = "/run/electric-eye/electric-eye.sock";
#[cfg(test)]
const ACTIVITY_LIMIT: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ns: u64,
    pub boot_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub ts_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_result: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_resolution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_info: Option<crate::process::ProcessRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_identity: Option<crate::provenance::FileIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<crate::grouping::Attribution>,
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
    pub name: Option<String>,
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
    apps: crate::cache::Recent<AppStat>,
    incidents: VecDeque<Value>,
    store: Option<StoreClient>,
    capture_loss: Vec<u64>,
    processes: crate::cache::Recent<crate::process::ProcessRecord>,
    documents: HashMap<String, crate::cache::Recent<Value>>,
    mcp_socket: Option<String>,
    config: crate::config::Config,
}

impl SharedState {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_config(crate::config::Config::default())
    }
    pub fn with_config(config: crate::config::Config) -> Self {
        let limits = &config.limits;
        Self {
            started: Instant::now(),
            attached: Vec::new(),
            skipped: Vec::new(),
            events_total: 0,
            activity: VecDeque::new(),
            apps: crate::cache::Recent::new(limits.app_entries),
            incidents: VecDeque::new(),
            store: None,
            capture_loss: vec![],
            processes: crate::cache::Recent::new(limits.process_entries),
            documents: HashMap::new(),
            mcp_socket: None,
            config,
        }
    }

    pub fn record_process(&mut self, p: crate::process::ProcessRecord) {
        self.processes.insert(p.id.clone(), p.last_seen_ms, p);
    }
    pub fn record_document(
        &mut self,
        collection: &str,
        key: &str,
        ts: u64,
        value: &impl Serialize,
    ) {
        if let Ok(value) = serde_json::to_value(value) {
            self.documents
                .entry(collection.into())
                .or_insert_with(|| crate::cache::Recent::new(self.config.limits.document_entries))
                .insert(key.into(), ts, value);
        }
    }
    pub(crate) fn documents(&self, collection: &str, limit: usize) -> Vec<Value> {
        self.documents
            .get(collection)
            .map(|c| c.recent(limit).cloned().collect())
            .unwrap_or_default()
    }
    fn matching_activity(&self, op: &str, selector: &str, limit: usize) -> Value {
        let activity: Vec<_> = self
            .activity
            .iter()
            .rev()
            .filter(|e| match op {
                "app" => {
                    event_comm(&e.event) == selector
                        || e.application.as_ref().is_some_and(|a| {
                            a.id == selector || a.name == selector || a.task_id == selector
                        })
                }
                "network" => matches!(
                    e.event,
                    ObservedEvent::Connect(_)
                        | ObservedEvent::Accept(_)
                        | ObservedEvent::Listen(_)
                        | ObservedEvent::Traffic(_)
                ),
                _ => match &e.event {
                    ObservedEvent::FileRead(f)
                    | ObservedEvent::FileOpen(f)
                    | ObservedEvent::FileWrite(f)
                    | ObservedEvent::FileUnlink(f) => f.path == selector,
                    ObservedEvent::FileRename(f) => {
                        f.from_path == selector || f.to_path == selector
                    }
                    _ => false,
                },
            })
            .take(limit)
            .collect();
        json!({"activity":activity,"history":"recent in-memory observations; persistence disabled"})
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
        while self.incidents.len() > self.config.limits.incident_entries {
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

    pub(crate) fn config_snapshot(&self) -> crate::config::Config {
        self.config.clone()
    }

    pub fn set_capture_loss(&mut self, counts: Vec<u64>) {
        self.capture_loss = counts;
    }

    pub fn set_probes(&mut self, attached: Vec<String>, skipped: Vec<String>) {
        self.attached = attached;
        self.skipped = skipped;
    }

    pub fn set_mcp_socket(&mut self, socket: Option<String>) {
        self.mcp_socket = socket;
    }

    pub fn record(&mut self, entry: ActivityEntry) {
        self.events_total += 1;
        let comm = entry
            .application
            .as_ref()
            .map(|a| a.id.clone())
            .unwrap_or_else(|| event_comm(&entry.event));
        let mut stats = self.apps.get(&comm).cloned().unwrap_or_default();
        if let Some(app) = &entry.application {
            stats.name = Some(app.name.clone());
        }
        match &entry.event {
            ObservedEvent::Traffic(summary) => {
                stats.sent += summary.sent;
                stats.recv += summary.recv;
            }
            _ => stats.events += 1,
        }

        self.apps.insert(comm, entry.ts_ms, stats);
        self.activity.push_back(entry);
        while self.activity.len() > self.config.limits.activity_entries {
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
            "mcp_socket": self.mcp_socket,
            "config": self.config,
        })
    }

    pub fn activity_value(&self, limit: usize) -> Value {
        let entries: Vec<&ActivityEntry> = self.activity.iter().rev().take(limit).collect();
        let rows: Vec<Value> = entries
            .iter()
            .map(|entry| serde_json::to_value(entry).unwrap())
            .collect();
        let overview = activity_overview(&rows);
        json!({ "activity": entries,"overview":overview })
    }

    pub fn apps_value(&self) -> Value {
        let mut contexts: HashMap<String, BTreeSet<String>> = HashMap::new();
        if let Some(flows) = self.documents.get("flows") {
            for flow in flows.values() {
                let Some(label) = flow["network_context"]["label"].as_str() else {
                    continue;
                };
                for name in [
                    flow["application"]["name"].as_str(),
                    flow["application"]["id"].as_str(),
                ]
                .into_iter()
                .flatten()
                {
                    if !name.is_empty() {
                        contexts
                            .entry(name.to_string())
                            .or_default()
                            .insert(label.to_string());
                    }
                }
                if let Some(contributors) = flow["contributors"].as_object() {
                    for contributor in contributors.values() {
                        if let Some(comm) = contributor["comm"].as_str() {
                            contexts
                                .entry(comm.to_string())
                                .or_default()
                                .insert(label.to_string());
                        }
                    }
                }
            }
        }
        let mut apps: Vec<(&String, &AppStat)> = self.apps.entries().collect();
        apps.sort_by_key(|a| std::cmp::Reverse(a.1.events + a.1.sent + a.1.recv));
        let apps: Vec<Value> = apps
            .into_iter()
            .map(|(comm, stat)| {
                let name = stat.name.as_deref().unwrap_or(comm);
                let mut labels: BTreeSet<String> = BTreeSet::new();
                if let Some(values) = contexts.get(name) {
                    labels.extend(values.iter().cloned());
                }
                if let Some(values) = contexts.get(comm) {
                    labels.extend(values.iter().cloned());
                }
                json!({
                    "comm": comm,
                    "name": name,
                    "events": stat.events,
                    "sent": stat.sent,
                    "recv": stat.recv,
                    "contexts": labels.into_iter().collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({ "apps": apps })
    }
}

fn activity_overview(entries: &[Value]) -> Value {
    let mut groups: std::collections::BTreeMap<(String, String), BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for entry in entries {
        let event = &entry["event"];
        if event["event"] != "file_write"
            || event["kind"] != "write"
            || entry["syscall_result"]
                .as_i64()
                .is_some_and(|result| result < 0)
        {
            continue;
        }
        let Some(path) = event["path"].as_str() else {
            continue;
        };
        let name = entry["application"]["name"]
            .as_str()
            .or_else(|| event["comm"].as_str())
            .unwrap_or("unknown");
        let directory = Path::new(path)
            .parent()
            .unwrap_or(Path::new(""))
            .display()
            .to_string();
        groups
            .entry((name.into(), directory))
            .or_default()
            .insert(path.into());
    }
    json!(groups.into_iter().map(|((name,dir),files)| json!({"text":format!("{name} modified {} observed files under {dir}",files.len()),"files":files,"confidence":"observed"})).collect::<Vec<_>>())
}

fn event_comm(event: &ObservedEvent) -> String {
    match event {
        ObservedEvent::Exec(event) | ObservedEvent::Fork(event) => event.comm.clone(),
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
    pub(crate) listener: UnixListener,
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

#[cfg(test)]
const MAX_REQUEST_BYTES: usize = 16 * 1024;

pub struct ApiServer {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}
impl ApiServer {
    pub fn start(socket: SocketGuard, state: Arc<Mutex<SharedState>>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let limits = state.lock().unwrap().config.limits.clone();
        let join = std::thread::Builder::new()
            .name("electric-eye-api".into())
            .spawn(move || {
                let mut workers = Vec::new();
                let mut queues = Vec::new();
                for _ in 0..limits.api_workers {
                    let (tx, rx) = sync_channel::<UnixStream>(limits.api_queue);
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
                    for _ in 0..limits.api_accept_batch {
                        match socket.listener.accept() {
                            Ok((mut stream, _)) => {
                                for _ in 0..limits.api_workers {
                                    let index = next;
                                    next = (next + 1) % limits.api_workers;
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
                    std::thread::sleep(Duration::from_millis(limits.api_poll_ms));
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
#[cfg(test)]
fn read_request(stream: &mut UnixStream) -> io::Result<String> {
    read_request_with_limits(stream, &crate::config::Limits::default())
}
fn read_request_with_limits(
    stream: &mut UnixStream,
    limits: &crate::config::Limits,
) -> io::Result<String> {
    let deadline = Instant::now() + Duration::from_millis(limits.api_timeout_ms);
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
        if line.len() + count > limits.api_request_bytes {
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
    let limits = state.lock().unwrap().config.limits.clone();
    let line = read_request_with_limits(&mut stream, &limits)?;
    let request: Value = serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({}));
    let response = response_for(&request, state);

    let mut response = serde_json::to_vec(&response)?;
    response.push(b'\n');
    let deadline = Instant::now() + Duration::from_millis(limits.api_timeout_ms);
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

fn merge_documents(
    saved: Vec<Value>,
    live: Vec<Value>,
    collection: &str,
    limit: usize,
) -> Vec<Value> {
    let mut values = HashMap::new();
    for row in saved.into_iter().chain(live) {
        let id = if collection == "applications" {
            row["attribution"]["task_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        } else if collection == "execs" {
            format!(
                "{}:{}",
                row["id"].as_str().unwrap_or_default(),
                row["exec_id"]
            )
        } else {
            row["id"].as_str().unwrap_or_default().to_string()
        };
        values.insert(id, row);
    }
    let mut values: Vec<_> = values.into_values().collect();
    values.sort_by_key(|v| {
        std::cmp::Reverse(
            ["last_seen_ms", "last_ms", "ts_ms", "first_seen_ms"]
                .iter()
                .find_map(|k| v[k].as_u64())
                .unwrap_or(0),
        )
    });
    values.truncate(limit);
    values
}
fn merge_events(saved: Vec<Value>, live: Vec<Value>, limit: usize) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut events: Vec<_> = live
        .into_iter()
        .chain(saved)
        .filter(|e| {
            seen.insert(
                e["event_id"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| e.to_string()),
            )
        })
        .collect();
    events.sort_by_key(|v| std::cmp::Reverse(v["ts_ms"].as_u64().unwrap_or(0)));
    events.truncate(limit);
    events
}
pub(crate) fn in_window(value: &Value, since: Option<u64>, before: Option<u64>) -> bool {
    let ts = value["ts_ms"].as_u64().unwrap_or(0);
    since.is_none_or(|since| ts >= since) && before.is_none_or(|before| ts < before)
}
pub(crate) fn cursor_key(value: &Value, kind: &str) -> (u64, String) {
    let id = if kind == "activity" {
        value["event_id"].as_str()
    } else {
        value["id"].as_str()
    }
    .map(str::to_string)
    .unwrap_or_else(|| value.to_string());
    (value["ts_ms"].as_u64().unwrap_or(0), id)
}
fn sort_rows(values: &mut [Value], kind: &str) {
    values.sort_by_key(|left| std::cmp::Reverse(cursor_key(left, kind)));
}
fn parse_cursor(cursor: &str) -> Option<(u64, String)> {
    let (ts, id) = cursor.split_once('|')?;
    Some((ts.parse().ok()?, id.to_string()))
}
fn next_cursor(values: &[Value], has_more: bool, kind: &str) -> Value {
    if !has_more {
        return Value::Null;
    }
    values
        .last()
        .map(|value| {
            let (ts, id) = cursor_key(value, kind);
            Value::String(format!("{ts}|{id}"))
        })
        .unwrap_or(Value::Null)
}

#[derive(Default)]
pub(crate) struct HistoryQuery {
    pub since_ms: Option<u64>,
    pub before_ms: Option<u64>,
    pub cursor: Option<(u64, String)>,
}

impl HistoryQuery {
    pub fn matches(&self, value: &Value, kind: &str) -> bool {
        in_window(value, self.since_ms, self.before_ms)
            && self
                .cursor
                .as_ref()
                .is_none_or(|cursor| cursor_key(value, kind) < *cursor)
    }
}

fn focus_value_matches(rule: &crate::config::FocusRule, value: &Value) -> bool {
    let text = value.to_string().to_ascii_lowercase();
    let application_match = rule.applications.is_empty()
        || rule
            .applications
            .iter()
            .any(|candidate| text.contains(&candidate.to_ascii_lowercase()));
    let path_match = rule.paths.is_empty()
        || rule
            .paths
            .iter()
            .any(|prefix| text.contains(&prefix.to_ascii_lowercase()));
    application_match && path_match
}

pub(crate) fn response_for(request: &Value, state: &Arc<Mutex<SharedState>>) -> Value {
    let limits = state.lock().unwrap().config.limits.clone();
    let op = request["op"].as_str().unwrap_or_default();
    let limit = request["limit"]
        .as_u64()
        .unwrap_or(100)
        .clamp(1, limits.api_query_rows as u64) as usize;
    let since_ms = request["since_ms"].as_u64();
    let before_ms = request["before_ms"].as_u64();

    let store = state.lock().unwrap().store_client();
    let query = |result: anyhow::Result<Value>| {
        result.unwrap_or_else(|err| json!({ "error": format!("{err:#}") }))
    };

    match op {
        "processes" | "process" | "tree" => {
            let selector = request["process"].as_str().unwrap_or_default();
            if op == "process" && selector.is_empty() {
                return json!({"error":"process requires a PID or stable identity"});
            }
            let mut rows = std::collections::BTreeMap::new();
            if let Some(store) = &store
                && let Ok(saved) =
                    store.process_documents(selector, op == "tree", limits.api_process_rows + 1)
            {
                for p in saved {
                    if let Some(id) = p["id"].as_str() {
                        rows.insert(id.to_string(), p);
                    }
                }
            }
            for p in state.lock().unwrap().processes.values() {
                if rows.get(&p.id).is_none_or(|saved| {
                    saved["last_seen_ms"].as_u64().unwrap_or(0) < p.last_seen_ms
                }) {
                    rows.insert(p.id.clone(), json!(p));
                }
            }
            let aliases: HashMap<_, _> = rows
                .values()
                .filter_map(|p| {
                    Some((
                        p["id"].as_str()?.to_string(),
                        rows.get(p["superseded_by"].as_str()?)?["identity"].clone(),
                    ))
                })
                .collect();
            for p in rows.values_mut() {
                if let Ok(parent) = serde_json::from_value::<ProcessIdentity>(p["parent"].clone())
                    && let Some(exact) = aliases.get(&crate::process::key(&parent))
                {
                    p["parent"] = exact.clone();
                }
            }
            let selected: Vec<_> = rows
                .values()
                .filter(|p| {
                    p["superseded_by"].is_null()
                        && (selector.is_empty()
                            || p["id"] == selector
                            || selector
                                .parse::<u64>()
                                .ok()
                                .is_some_and(|pid| p["identity"]["pid"].as_u64() == Some(pid)))
                })
                .cloned()
                .collect();
            let mut result = selected.clone();
            if op == "tree" && !selector.is_empty() {
                let mut ids: std::collections::HashSet<String> = selected
                    .iter()
                    .filter_map(|p| p["id"].as_str().map(str::to_string))
                    .collect();
                loop {
                    let mut added = false;
                    for p in rows.values() {
                        if p["superseded_by"].is_null()
                            && !ids.contains(p["id"].as_str().unwrap_or_default())
                        {
                            let parent: Option<ProcessIdentity> =
                                serde_json::from_value(p["parent"].clone()).ok();
                            if parent
                                .as_ref()
                                .is_some_and(|parent| ids.contains(&crate::process::key(parent)))
                            {
                                ids.insert(p["id"].as_str().unwrap_or_default().into());
                                result.push(p.clone());
                                added = true;
                            }
                        }
                    }
                    if !added {
                        break;
                    }
                }
            }
            result.sort_by_key(|p| std::cmp::Reverse(p["last_seen_ms"].as_u64().unwrap_or(0)));
            let truncated = result.len() > limits.api_process_rows;
            result.truncate(limits.api_process_rows);
            let ids: Vec<_> = result
                .iter()
                .filter_map(|p| p["id"].as_str().map(str::to_string))
                .collect();
            let saved = store
                .as_ref()
                .and_then(|s| s.exec_history(&ids, limits.api_process_rows + 1).ok())
                .unwrap_or_default();
            let live = state
                .lock()
                .unwrap()
                .documents("execs", limits.document_entries)
                .into_iter()
                .filter(|p| ids.iter().any(|id| p["id"] == *id))
                .collect();
            let execs = merge_documents(saved, live, "execs", limits.api_process_rows);
            json!({"processes":result,"execs":execs,"inventory_truncated":truncated,"execs_truncated":execs.len()>=limits.api_process_rows})
        }
        "summaries" | "flows" => {
            let saved = store
                .as_ref()
                .and_then(|s| s.documents(op, limit).ok())
                .unwrap_or_default();
            let live = state.lock().unwrap().documents(op, limit);
            json!({op:merge_documents(saved,live,op,limit),"history":if store.is_some(){"persisted and recent"}else{"recent in-memory observations; persistence disabled"}})
        }
        "status" => {
            let mut value = state.lock().unwrap().status_value();
            value["store"] = store
                .as_ref()
                .map(StoreClient::status_value)
                .unwrap_or(Value::Null);
            value
        }
        "activity" => {
            let history = HistoryQuery {
                since_ms,
                before_ms,
                cursor: request["before_cursor"].as_str().and_then(parse_cursor),
            };
            if request["before_cursor"].is_string() && history.cursor.is_none() {
                return json!({"error":"invalid history cursor"});
            }
            let mut value = {
                let state = state.lock().unwrap();
                state.activity_value(state.activity.len())
            };
            let live = value["activity"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|row| history.matches(row, "activity"))
                .collect();
            let saved = match &store {
                Some(store) => match store.events_page(&history, limit + 1) {
                    Ok(rows) => rows,
                    Err(error) => return json!({"error":format!("{error:#}")}),
                },
                None => Vec::new(),
            };
            let mut rows = merge_events(saved, live, usize::MAX);
            sort_rows(&mut rows, "activity");
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            value["next_cursor"] = next_cursor(&rows, has_more, "activity");
            value["activity"] = json!(rows);
            // The overview must describe the selected page, rather than newer
            // observations outside the requested window.
            value["overview"] = activity_overview(&rows);
            if let Some(store) = &store
                && let Ok(persisted) = store.recent_activities(20)
            {
                value["persisted_activities"] = persisted["activities"].clone();
            }
            value
        }
        "apps" => {
            let mut value = state.lock().unwrap().apps_value();
            let saved = store
                .as_ref()
                .and_then(|s| s.documents("applications", limit).ok())
                .unwrap_or_default();
            let live = state.lock().unwrap().documents("applications", limit);
            value["tasks"] = json!(merge_documents(saved, live, "applications", limit));
            value
        }
        "incidents" => {
            let history = HistoryQuery {
                since_ms,
                before_ms,
                cursor: request["before_cursor"].as_str().and_then(parse_cursor),
            };
            if request["before_cursor"].is_string() && history.cursor.is_none() {
                return json!({"error":"invalid history cursor"});
            }
            let live = {
                let state = state.lock().unwrap();
                state.recent_incidents(state.incidents.len())
            }
            .into_iter()
            .filter(|row| history.matches(row, "incidents"))
            .collect();
            let saved = match &store {
                Some(store) => match store.incidents_page(&history, limit + 1) {
                    Ok(rows) => rows,
                    Err(error) => return json!({"error":format!("{error:#}")}),
                },
                None => Vec::new(),
            };
            let mut rows = merge_documents(saved, live, "incidents", usize::MAX);
            sort_rows(&mut rows, "incidents");
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            json!({"incidents":rows,"next_cursor":next_cursor(&rows,has_more,"incidents")})
        }
        "investigate" => {
            let id = request["id"].as_str().unwrap_or_default();
            if id.is_empty() {
                return json!({"error":"investigate requires an incident id"});
            }
            let recent = {
                let state = state.lock().unwrap();
                state
                    .incidents
                    .iter()
                    .find(|row| row["id"].as_str() == Some(id))
                    .cloned()
            };
            let incident = match recent {
                Some(incident) => Some(incident),
                None => match &store {
                    Some(store) => match store.incident(id) {
                        Ok(incident) => incident,
                        Err(error) => return json!({"error":format!("{error:#}")}),
                    },
                    None => None,
                },
            };
            let Some(incident) = incident else {
                return json!({"error":format!("incident {id} not found in retained history")});
            };
            let config = state.lock().unwrap().config_snapshot();
            let home = incident["details"]["actor"]["uid"]
                .as_u64()
                .and_then(|uid| crate::net_context::home_for_uid(uid as u32));
            let bundle = crate::investigate::bundle(&incident, &config, home.as_deref());
            json!({"incident": incident, "investigation": bundle, "prompt": bundle["prompt"]})
        }
        "focus" => {
            let config = state.lock().unwrap().config_snapshot();
            let activity = state.lock().unwrap().activity_value(limit);
            let activity = activity["activity"].as_array().cloned().unwrap_or_default();
            let mut flows = state.lock().unwrap().documents("flows", limit);
            let mut incidents = state.lock().unwrap().recent_incidents(limit);
            if let Some(store) = &store {
                if let Ok(value) = store.documents("flows", limit) {
                    flows.extend(value);
                }
                if let Ok(value) = store.incidents(limit) {
                    incidents.extend(value["incidents"].as_array().cloned().unwrap_or_default());
                }
            }
            let rules: Vec<Value> = config
                .focus
                .iter()
                .map(|rule| {
                    let matching_activity: Vec<&Value> = activity
                        .iter()
                        .filter(|row| focus_value_matches(rule, row))
                        .collect();
                    let matching_flows: Vec<&Value> = flows
                        .iter()
                        .filter(|row| focus_value_matches(rule, row))
                        .collect();
                    let matching_incidents: Vec<&Value> = incidents
                        .iter()
                        .filter(|row| focus_value_matches(rule, row))
                        .collect();
                    let first = matching_activity.first().copied();
                    let actor = first
                        .map(|row| &row["process_info"])
                        .unwrap_or(&Value::Null);
                    let app = actor["application"]["name"]
                        .as_str()
                        .or_else(|| first.and_then(|row| row["event"]["comm"].as_str()))
                        .unwrap_or_default();
                    let comm = actor["comm"].as_str().unwrap_or(app);
                    let executable = actor["executable"].as_str().unwrap_or_default();
                    let cwd = actor["cwd"].as_str();
                    let home = actor["uid"]
                        .as_u64()
                        .and_then(|uid| crate::net_context::home_for_uid(uid as u32));
                    let logs = if rule.log_paths.is_empty() {
                        crate::investigate::detected_log_paths(
                            app,
                            comm,
                            executable,
                            cwd,
                            home.as_deref(),
                        )
                    } else {
                        crate::investigate::expand_paths(&rule.log_paths, home.as_deref())
                    };
                    let mut apps: Vec<String> = matching_activity
                        .iter()
                        .filter_map(|row| {
                            row["application"]["name"]
                                .as_str()
                                .or_else(|| row["event"]["comm"].as_str())
                                .map(str::to_string)
                        })
                        .collect();
                    apps.sort();
                    apps.dedup();
                    json!({
                        "name": rule.name,
                        "applications": rule.applications,
                        "paths": rule.paths,
                        "activity": matching_activity.len(),
                        "flows": matching_flows.len(),
                        "incidents": matching_incidents.len(),
                        "activity_rows": matching_activity,
                        "flow_rows": matching_flows,
                        "incident_rows": matching_incidents,
                        "apps": apps,
                        "latest": matching_activity.iter().take(3).copied().collect::<Vec<_>>(),
                        "harness_logs": crate::investigate::describe_files(&logs),
                    })
                })
                .collect();
            json!({"focus": rules, "window": {"activity_rows": activity.len(), "flow_rows": flows.len(), "incidents": incidents.len()}, "configured": !config.focus.is_empty()})
        }
        "file" => {
            let path = request["path"].as_str().unwrap_or_default();
            if path.is_empty() {
                json!({ "error": "file requires a path" })
            } else {
                match &store {
                    Some(store) => query(store.file_activities(path, limit)),
                    None => state.lock().unwrap().matching_activity(
                        op,
                        request["path"].as_str().unwrap_or_default(),
                        limit,
                    ),
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
                    None => state.lock().unwrap().matching_activity(op, app, limit),
                }
            }
        }
        "network" => match &store {
            Some(store) => query(store.network_activities(limit)),
            None => state.lock().unwrap().matching_activity(
                op,
                request["path"].as_str().unwrap_or_default(),
                limit,
            ),
        },
        "noise" => crate::noise::value(store.as_ref(), state, limit),
        "config" => {
            let config = state.lock().unwrap().config_snapshot();
            json!({
                "config": config,
                "toml": toml::to_string_pretty(&config).unwrap_or_default(),
            })
        }
        "db" => match &store {
            Some(store) => {
                let config = state.lock().unwrap().config_snapshot();
                query(store.db_status(&config))
            }
            None => json!({ "error": "SQLite persistence is disabled" }),
        },
        "db_compact" => match &store {
            Some(store) => query(store.compact()),
            None => json!({ "error": "SQLite persistence is disabled" }),
        },
        "why" => {
            let path = request["path"].as_str().unwrap_or_default();
            if path.is_empty() {
                json!({ "error": "why requires a path" })
            } else {
                match &store {
                    Some(store) => query(store.why(path, limit)),
                    None => state.lock().unwrap().matching_activity(
                        op,
                        request["path"].as_str().unwrap_or_default(),
                        limit,
                    ),
                }
            }
        }
        "" => json!({ "error": "missing op" }),
        other => json!({ "error": format!("unknown op {other}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use electric_eye_core::{ExecEvent, FileEvent, FileKind};
    use std::path::PathBuf;

    fn entry(pid: u32, comm: &str) -> ActivityEntry {
        ActivityEntry {
            executable_identity: None,
            ts_ms: now_ms(),
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
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
            executable_identity: None,
            ts_ms: now_ms(),
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
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

    #[test]
    fn apps_expose_network_contexts_from_flows() {
        let mut state = SharedState::new();
        state.record(entry(1, "curl"));
        state.record_document(
            "flows",
            "flow-1",
            1,
            &json!({
                "application": {"name": "curl", "id": "executable:curl"},
                "network_context": {"label": "vopono:vo_test", "kind": "vopono"},
                "contributors": {}
            }),
        );
        let value = state.apps_value();
        assert_eq!(value["apps"][0]["contexts"][0], "vopono:vo_test");
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

#[cfg(test)]
mod usability_regressions {
    use super::*;
    #[test]
    fn no_database_keeps_live_flows_summaries_tasks_and_history_usable() {
        let state = Arc::new(Mutex::new(SharedState::new()));
        state.lock().unwrap().record_document(
            "flows",
            "flow-1",
            10,
            &json!({"id":"flow-1","last_seen_ms":10,"sent":4}),
        );
        state.lock().unwrap().record_document(
            "summaries",
            "summary-1",
            10,
            &json!({"id":"summary-1","last_ms":10}),
        );
        state.lock().unwrap().record_document(
            "applications",
            "task-1",
            10,
            &json!({"attribution":{"task_id":"task-1"},"last_seen_ms":10}),
        );
        for op in ["flows", "summaries"] {
            let response = response_for(&json!({"op":op}), &state);
            assert_eq!(response[op].as_array().unwrap().len(), 1, "{response}");
            assert!(response["error"].is_null());
        }
        assert_eq!(
            response_for(&json!({"op":"apps"}), &state)["tasks"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        for op in ["file", "why", "app", "network"] {
            let response = response_for(&json!({"op":op,"path":"/work/a","app":"test"}), &state);
            assert!(response["activity"].is_array(), "{response}");
            assert!(response["error"].is_null());
        }
    }
    #[test]
    fn current_incident_enrichment_overrides_the_persisted_base_record() {
        let merged = merge_documents(
            vec![json!({"id":"a","details":null,"ts_ms":1})],
            vec![json!({"id":"a","details":{"journal":"context"},"ts_ms":1})],
            "incidents",
            10,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0]["details"]["journal"], "context");
    }
    #[test]
    fn restored_raw_activity_is_visible_without_duplicate_live_entries() {
        let old = json!({"event_id":"same","ts_ms":1});
        let fresh = json!({"event_id":"new","ts_ms":2});
        assert_eq!(
            merge_events(vec![old.clone()], vec![old, fresh.clone()], 10),
            vec![fresh, json!({"event_id":"same","ts_ms":1})]
        );
    }
}

#[cfg(test)]
mod history_regressions {
    use super::*;
    fn populate(state: &Arc<Mutex<SharedState>>, store: Option<&StoreClient>) -> u64 {
        let timestamp = now_ms();
        for index in 0..10 {
            let ts_ms = timestamp + index / 2;
            let entry = ActivityEntry {
                executable_identity: None,
                ts_ms,
                event_id: (index != 0).then(|| format!("event-{index:02}")),
                syscall_result: None,
                process: None,
                path_resolution: None,
                process_info: None,
                application: None,
                unit: None,
                nix: None,
                parent: None,
                exe: None,
                event: ObservedEvent::Exit(electric_eye_core::ExitEvent {
                    pid: index as u32,
                    uid: 1000,
                    comm: "fixture".into(),
                }),
            };
            let id = format!("incident-{index:02}");
            let incident =
                json!({"id":id,"ts_ms":ts_ms,"severity":"high","title":"fixture","details":{}});
            if let Some(store) = store {
                store.record(&entry);
                store.record_incident(crate::store::IncidentRow {
                    ts_ms: ts_ms as i64,
                    id: id.clone(),
                    json: incident.to_string(),
                    severity: "high".into(),
                    title: "fixture".into(),
                    details: "{}".into(),
                });
            }
            if store.is_none() || index >= 7 {
                state.lock().unwrap().record(entry);
                state.lock().unwrap().record_incident(incident);
            }
        }
        timestamp
    }
    fn pages(state: &Arc<Mutex<SharedState>>, op: &str, timestamp: Option<u64>) -> Vec<Value> {
        let mut cursor = Value::Null;
        let mut all = Vec::new();
        for _ in 0..20 {
            let mut request = json!({"op":op,"limit":2});
            if cursor.is_string() {
                request["before_cursor"] = cursor;
            }
            if let Some(timestamp) = timestamp {
                request["since_ms"] = json!(timestamp + 1);
                request["before_ms"] = json!(timestamp + 3);
            }
            let response = response_for(&request, state);
            assert!(response["error"].is_null(), "{response}");
            let rows = response[op].as_array().unwrap();
            all.extend(rows.iter().cloned());
            cursor = response["next_cursor"].clone();
            if cursor.is_null() {
                return all;
            }
            assert!(!rows.is_empty());
        }
        panic!("pagination did not terminate");
    }
    #[test]
    fn filters_and_cursors_reach_all_retained_rows_with_and_without_sqlite() {
        for persisted in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let mut config = crate::config::Config::default();
            config.limits.api_query_rows = 3;
            let state = Arc::new(Mutex::new(SharedState::with_config(config.clone())));
            let store = persisted.then(|| {
                crate::store::Store::open_with_config(&temp.path().join("history.db"), config)
                    .unwrap()
            });
            let client = store.as_ref().map(|store| store.client());
            let timestamp = populate(&state, client.as_ref());
            if let Some(store) = store {
                store.shutdown();
            }
            state.lock().unwrap().set_store(client);
            for op in ["activity", "incidents"] {
                let rows = pages(&state, op, None);
                assert_eq!(rows.len(), 10, "{op}, persisted={persisted}");
                let keys: BTreeSet<_> = rows.iter().map(|row| cursor_key(row, op)).collect();
                assert_eq!(keys.len(), 10);
                assert!(
                    rows.windows(2)
                        .all(|pair| cursor_key(&pair[0], op) > cursor_key(&pair[1], op))
                );
                let filtered = pages(&state, op, Some(timestamp));
                assert_eq!(filtered.len(), 4);
                assert!(filtered.iter().all(|row| in_window(
                    row,
                    Some(timestamp + 1),
                    Some(timestamp + 3)
                )));
                let older =
                    response_for(&json!({"op":op,"before_ms":timestamp+1,"limit":2}), &state);
                assert_eq!(older[op].as_array().unwrap().len(), 2);
                assert!(older["next_cursor"].is_null());
            }
            let oldest = response_for(&json!({"op":"investigate","id":"incident-00"}), &state);
            assert_eq!(oldest["incident"]["id"], "incident-00");
            assert!(oldest["error"].is_null());
        }
    }
    #[test]
    fn invalid_cursors_are_rejected_instead_of_restarting_pagination() {
        let state = Arc::new(Mutex::new(SharedState::new()));
        for op in ["activity", "incidents"] {
            assert!(
                response_for(&json!({"op":op,"before_cursor":"invalid"}), &state)["error"]
                    .is_string()
            );
        }
    }
}
