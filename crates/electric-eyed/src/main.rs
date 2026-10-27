mod api;
mod btf;
mod cache;
mod collector;
mod config;
mod container;
mod correlation;
mod dns;
mod enrich;
mod flows;
mod format;
mod grouping;
mod investigate;
mod journald;
mod known_hosts;
mod mcp;
mod net_context;
mod noise;
mod probe;
mod process;
mod provenance;
mod rules;
mod store;
mod vopono;
#[path = "../../electric-eye-core/src/wire.rs"]
mod wire;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api::{ActivityEntry, ProcessIdentity};
use collector::Collector;
use electric_eye_core::{
    ExecEvent, ExitEvent, FileEvent, FileKind, NetEvent, ObservedEvent, RenameEvent, TrafficSummary,
};
use electric_eye_nix::ProvenanceRegistry;

const DEFAULT_OBJECT: &str = "target/bpfel-unknown-none/release/electric-eye-ebpf";
const INSTALLED_OBJECT: &str = "/usr/lib/electric-eye/electric-eye-ebpf";
struct WriteStat {
    entry: ActivityEntry,
    count: u64,
    bytes: u64,
}
struct TrafficStat {
    entry: ActivityEntry,
    sent: u64,
    recv: u64,
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            request_shutdown as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            request_shutdown as *const () as libc::sighandler_t,
        );
    }
}

#[derive(Debug)]
struct Options {
    stdout: bool,
    json: bool,
    no_bpf: bool,
    no_socket: bool,
    no_mcp: bool,
    no_db: bool,
    socket: Option<PathBuf>,
    mcp_socket: Option<PathBuf>,
    mcp_tools: Option<String>,
    db: Option<PathBuf>,
    object_override: Option<PathBuf>,
    config: Option<PathBuf>,
    check_config: bool,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options {
            stdout: false,
            json: false,
            no_bpf: false,
            no_socket: false,
            no_mcp: false,
            no_db: false,
            socket: None,
            mcp_socket: None,
            mcp_tools: None,
            db: None,
            object_override: None,
            config: None,
            check_config: false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--config" => {
                    options.config = Some(PathBuf::from(
                        iter.next().ok_or("--config requires a path")?,
                    ));
                }
                "--stdout" => options.stdout = true,
                "--json" => options.json = true,
                "--check-config" => options.check_config = true,
                "--no-bpf" => options.no_bpf = true,
                "--no-socket" => options.no_socket = true,
                "--no-mcp" => options.no_mcp = true,
                "--no-db" => options.no_db = true,
                "--socket" => {
                    let Some(value) = iter.next() else {
                        return Err("--socket requires a path".into());
                    };
                    options.socket = Some(PathBuf::from(value));
                }
                "--mcp-socket" => {
                    let Some(value) = iter.next() else {
                        return Err("--mcp-socket requires a path".into());
                    };
                    options.mcp_socket = Some(PathBuf::from(value));
                }
                "--mcp-tools" => {
                    let Some(value) = iter.next() else {
                        return Err(
                            "--mcp-tools requires default, all, or a comma-separated list".into(),
                        );
                    };
                    options.mcp_tools = Some(value.clone());
                }
                "--db" => {
                    let Some(value) = iter.next() else {
                        return Err("--db requires a path".into());
                    };
                    options.db = Some(PathBuf::from(value));
                }
                "--ebpf-object" => {
                    let Some(value) = iter.next() else {
                        return Err("--ebpf-object requires a path".into());
                    };
                    options.object_override = Some(PathBuf::from(value));
                }
                other => return Err(format!("unknown argument {other}")),
            }
        }
        Ok(options)
    }
}

fn ebpf_object_path(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Some(env_path) = std::env::var_os("ELECTRIC_EYE_EBPF") {
        return PathBuf::from(env_path);
    }
    let installed = PathBuf::from(INSTALLED_OBJECT);
    if installed.exists() {
        return installed;
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(DEFAULT_OBJECT)
}

fn socket_path(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Some(env_path) = std::env::var_os("ELECTRIC_EYE_SOCKET") {
        return PathBuf::from(env_path);
    }
    PathBuf::from(api::DEFAULT_SOCKET)
}

fn mcp_socket_path(override_path: Option<&Path>) -> PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Some(env_path) = std::env::var_os("ELECTRIC_EYE_MCP_SOCKET") {
        return PathBuf::from(env_path);
    }
    PathBuf::from(mcp::DEFAULT_SOCKET)
}

fn database_path(override_path: Option<&Path>, disabled: bool) -> Option<PathBuf> {
    if disabled {
        return None;
    }
    if let Some(path) = override_path {
        return Some(path.to_path_buf());
    }
    if let Some(env_path) = std::env::var_os("ELECTRIC_EYE_DB") {
        return Some(PathBuf::from(env_path));
    }
    if let Some(state_dir) = std::env::var_os("STATE_DIRECTORY") {
        let first = std::env::split_paths(&state_dir).next();
        if let Some(dir) = first {
            return Some(dir.join("electric-eye.db"));
        }
    }
    let system_state = Path::new("/var/lib/electric-eye");
    if system_state.is_dir() {
        return Some(system_state.join("electric-eye.db"));
    }
    Some(PathBuf::from("electric-eye.db"))
}

fn classify_open(flags: u32) -> FileKind {
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;
    if flags & O_TRUNC != 0 {
        FileKind::Truncate
    } else if flags & O_CREAT != 0 {
        FileKind::Create
    } else {
        FileKind::Open
    }
}

fn print_banner(json: bool) {
    startup_line(json, "electric-eyed starting");
    startup_line(json, format!("kernel: {}", probe::kernel_release()));
    startup_line(
        json,
        format!(
            "BTF: {}",
            if probe::btf_available() {
                "available"
            } else {
                "unavailable"
            }
        ),
    );
}

/// Diagnostics go to stderr in JSON mode so stdout stays valid JSON Lines.
fn startup_line(json: bool, line: impl std::fmt::Display) {
    if json {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

#[derive(Hash, PartialEq, Eq)]
struct WriteKey {
    process: ProcessIdentity,
    exec_id: u32,
    exe: Option<String>,
    path: String,
    kind: FileKind,
}
#[derive(Hash, PartialEq, Eq)]
struct TrafficKey {
    process: ProcessIdentity,
    exec_id: u32,
    exe: Option<String>,
}
struct Session {
    registry: ProvenanceRegistry,
    write_window: HashMap<WriteKey, WriteStat>,
    traffic_window: HashMap<TrafficKey, TrafficStat>,
    dns: dns::DnsCache,
    anomalies: rules::AnomalyEngine,
    store: Option<store::StoreClient>,
    incidents: Option<journald::IncidentWorker>,
    json: bool,
    state: Arc<Mutex<api::SharedState>>,
    boot_id: String,
    boot_wall_ms: u64,
    processes: process::Registry,
    config: config::Config,
    provenance: Option<provenance::Provider>,
    groups: grouping::Groups,
    flows: flows::Tracker,
    correlation: correlation::Engine,
    udp_peers: cache::Recent<()>,
}
impl Session {
    fn entry(&self, raw: &wire::Record, event: ObservedEvent) -> ActivityEntry {
        let identity = ProcessIdentity {
            boot_id: self.boot_id.clone(),
            pid: raw.pid,
            start_ns: raw.start_ns,
        };
        let process = self.processes.get(&identity);
        let exe = collector::cstr(&raw.exe);
        let exe = (!exe.is_empty()).then_some(exe).or_else(|| {
            process
                .filter(|p| p.exec_id == raw.exec_id)
                .and_then(|p| p.executable.clone())
        });
        // The process registry is populated by process::observe before file and
        // network events are turned into ActivityEntry values. Avoid a
        // /proc/<pid>/stat read on every captured event at high event rates.
        let unit = process.and_then(|p| p.user_unit.clone().or_else(|| p.system_unit.clone()));
        let nix = exe
            .as_deref()
            .filter(|path| path.starts_with("/nix/store"))
            .and_then(|path| self.registry.identify(Path::new(path)).ok().flatten())
            .map(|p| p.to_string());
        ActivityEntry {
            ts_ms: self.boot_wall_ms.saturating_add(raw.ts_ns / 1_000_000),
            event_id: Some({
                static SEQUENCE: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                format!(
                    "{}:{}:{}:{}",
                    self.boot_id,
                    std::process::id(),
                    raw.ts_ns,
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                )
            }),
            syscall_result: matches!(
                raw.kind,
                wire::OPEN | wire::READ | wire::WRITE | wire::MMAP | wire::UNLINK | wire::RENAME
            )
            .then_some(raw.result),
            process: Some(identity),
            path_resolution: matches!(
                raw.kind,
                wire::OPEN | wire::READ | wire::WRITE | wire::MMAP | wire::UNLINK | wire::RENAME
            )
            .then(|| {
                match (
                    raw.path_resolution,
                    raw.kind == wire::RENAME && raw.path2_resolution != wire::PATH_KERNEL,
                ) {
                    (wire::PATH_KERNEL, false) => "kernel",
                    (wire::PATH_UNRESOLVED, _) => "unresolved",
                    _ if raw.kind == wire::RENAME
                        && raw.path2_resolution == wire::PATH_UNRESOLVED =>
                    {
                        "unresolved"
                    }
                    _ => "lexical",
                }
                .into()
            }),
            application: process.and_then(|p| p.application.clone()),
            process_info: if matches!(raw.kind, wire::EXEC | wire::FORK | wire::EXIT) {
                process.cloned()
            } else {
                None
            },
            event,
            unit,
            nix,
            parent: {
                let name = collector::cstr(&raw.parent_comm);
                (!name.is_empty()).then_some(name)
            },
            exe,
        }
    }
    fn analyze(&mut self, entry: &ActivityEntry) {
        for incident in self.anomalies.observe(entry) {
            self.emit_incident(incident);
        }
    }
    fn emit(&mut self, entry: ActivityEntry, display: bool, analyze: bool) {
        if display {
            if self.json {
                if let Ok(line) = serde_json::to_string(&entry) {
                    println!("{line}");
                }
            } else {
                let mut suffix = String::new();
                if let Some(unit) = &entry.unit {
                    suffix.push_str(&format!("  [{unit}]"));
                }
                if let Some(nix) = &entry.nix {
                    suffix.push_str(&format!("  (nix: {nix})"));
                }
                if entry.path_resolution.as_deref() == Some("unresolved") {
                    suffix.push_str("  [path unresolved]");
                }
                if let Some(result) = entry.syscall_result
                    && result < 0
                {
                    suffix.push_str(&format!("  [failed errno={}]", -result));
                }
                println!("{}{suffix}", entry.event);
            }
        }
        if let Some(store) = &self.store {
            store.record(&entry);
        }
        if analyze {
            self.analyze(&entry);
        }
        self.state.lock().unwrap().record(entry);
    }
    fn emit_incident(&mut self, mut incident: rules::Incident) {
        let actor = incident
            .process
            .as_ref()
            .and_then(|id| self.processes.get(id));
        let package_trust = actor
            .and_then(|actor| actor.executable.as_deref())
            .or(incident.exe.as_deref())
            .and_then(|exe| self.provenance.as_ref().map(|provider| provider.trust(exe)));
        if let Some(actor) = actor
            && let Some(details) = incident.details.as_object_mut()
        {
            details.insert("actor".into(), serde_json::json!(actor));
            if let Some(trust) = package_trust {
                details.insert("package_trust".into(), serde_json::json!(trust));
            }
        }
        // Persist the complete base record before optional, asynchronous context.
        if let Some(store) = &self.store {
            store.record_incident(store::IncidentRow::from_incident(&incident));
        }
        let mut value = serde_json::to_value(&incident).unwrap_or_default();
        value["event"] = serde_json::json!("incident");
        if self.json {
            println!("{value}");
        } else {
            println!(
                "INCIDENT  [{}] {}  ({} pid {}) {}",
                incident.severity.as_str(),
                incident.title,
                incident.comm,
                incident.pid,
                incident.path.as_deref().unwrap_or_default()
            );
        }
        self.state.lock().unwrap().record_incident(value);
        if let Some(worker) = &self.incidents {
            worker.enqueue(incident);
        }
    }
    fn udp_observation(&mut self, raw: &wire::Record) {
        if raw.remote_port == 0 || !matches!(raw.family, 2 | 10) {
            return;
        }
        let key = format!(
            "{}:{}:{}:{}:{}:{:?}:{}",
            raw.pid, raw.start_ns, raw.exec_id, raw.netns, raw.socket_id, raw.addr, raw.remote_port
        );
        let first = self.udp_peers.get(&key).is_none();
        self.udp_peers.insert(key, raw.ts_ns, ());
        let event = ObservedEvent::Connect(NetEvent {
            pid: raw.pid,
            uid: raw.uid,
            comm: collector::cstr(&raw.comm),
            family: raw.family,
            addr: raw.addr,
            local_port: raw.local_port as u16,
            remote_port: raw.remote_port as u16,
            hostname: dns::ip_from_addr(raw.family, raw.addr).and_then(|ip| self.dns.lookup(ip)),
            fd: None,
        });
        let entry = self.entry(raw, event);
        if first {
            self.emit(entry, true, true);
        } else {
            self.analyze(&entry);
        }
    }
    fn handle(&mut self, raw: wire::Record) {
        let timestamp = self.boot_wall_ms.saturating_add(raw.ts_ns / 1_000_000);
        if matches!(
            raw.kind,
            wire::READ | wire::OPEN | wire::WRITE | wire::MMAP | wire::UNLINK | wire::RENAME
        ) {
            let path = collector::cstr(&raw.path);
            let ignored = |path: &str| {
                self.config
                    .ignore_paths
                    .iter()
                    .any(|prefix| Path::new(path).starts_with(prefix))
            };
            let noisy = |path: &str| {
                self.config
                    .capture
                    .noise_paths
                    .iter()
                    .any(|prefix| Path::new(path).starts_with(prefix))
            };
            let drop_noise = raw.kind != wire::RENAME && noisy(&path);
            if drop_noise
                || (ignored(&path)
                    && (raw.kind != wire::RENAME || ignored(&collector::cstr(&raw.path2))))
            {
                return;
            }
        }
        if matches!(raw.kind, wire::NET_STATE | wire::NET_CLOSE) {
            for f in self.flows.observe(&raw, &self.boot_id, timestamp, None) {
                self.correlation.flow(&f);
                self.state
                    .lock()
                    .unwrap()
                    .record_document("flows", &f.id, timestamp, &f);
                if let Some(store) = &self.store {
                    store.document("flows", &f.id, timestamp, &f);
                }
            }
            return;
        }
        let p = self
            .processes
            .observe(&raw, &self.boot_id, timestamp, &self.config);
        let mut p = p;
        if (p.package.is_none() || raw.kind == wire::EXEC)
            && let (Some(provider), Some(exe)) = (&self.provenance, &p.executable)
        {
            p.package = Some(provider.identify_record(exe, &raw));
            self.processes.set_package(&p.identity, p.package.clone());
        }
        let changed =
            p.application.is_none() || matches!(raw.kind, wire::EXEC | wire::FORK | wire::EXIT);
        if changed {
            let parent = p.parent.as_ref().and_then(|id| self.processes.get(id));
            let app = self.groups.assign(&p, parent, &self.config);
            p.application = Some(app.clone());
            self.processes.set_application(&p.identity, app.clone());
            if let Some(group) = self.groups.applications.get(&app.task_id) {
                self.state.lock().unwrap().record_document(
                    "applications",
                    &app.task_id,
                    timestamp,
                    group,
                );
                if let Some(store) = &self.store {
                    store.document("applications", &app.task_id, timestamp, group);
                }
            }
        }
        self.state.lock().unwrap().record_process(p.clone());
        if raw.kind == wire::EXEC {
            self.state.lock().unwrap().record_document(
                "execs",
                &format!("{}:{}", p.id, p.exec_id),
                timestamp,
                &p,
            );
        }
        if let Some(store) = &self.store
            && (matches!(raw.kind, wire::EXEC | wire::FORK | wire::EXIT)
                || p.first_seen_ms == timestamp)
        {
            store.document("processes", &p.id, timestamp, &p);
            if raw.kind == wire::EXEC {
                store.document("execs", &format!("{}:{}", p.id, p.exec_id), timestamp, &p);
            }
        }
        for old in self.processes.drain_superseded() {
            self.state.lock().unwrap().record_process(old.clone());
            if let Some(store) = &self.store {
                store.document("processes", &old.id, old.last_seen_ms, &old);
            }
        }
        if raw.socket_id != 0 {
            for f in self.flows.observe(&raw, &self.boot_id, timestamp, Some(&p)) {
                self.correlation.flow(&f);
                self.state
                    .lock()
                    .unwrap()
                    .record_document("flows", &f.id, timestamp, &f);
                if let Some(store) = &self.store {
                    store.document("flows", &f.id, timestamp, &f);
                }
            }
        }
        if raw.protocol == 17
            && (raw.kind == wire::SENT
                || raw.kind == wire::NET_RESULT
                    && raw.flags != wire::FLAG_SO_ERROR
                    && raw.result == 0)
        {
            self.udp_observation(&raw);
        }
        if matches!(raw.kind, wire::SOCKET | wire::BIND | wire::NET_RESULT) {
            return;
        }
        let comm = collector::cstr(&raw.comm);
        let file_kind = match raw.kind {
            wire::READ => FileKind::Read,
            wire::WRITE => FileKind::Write,
            wire::MMAP => FileKind::Mmap,
            wire::UNLINK => FileKind::Unlink,
            _ => classify_open(raw.flags),
        };
        let event = match raw.kind {
            wire::EXEC | wire::FORK => {
                let e = ExecEvent {
                    pid: raw.pid,
                    ppid: raw.ppid,
                    uid: raw.uid,
                    comm,
                    exe: PathBuf::from(collector::cstr(&raw.exe)),
                    start_ticks: raw.start_ns
                        / (1_000_000_000
                            / (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64)),
                };
                if raw.kind == wire::FORK {
                    ObservedEvent::Fork(e)
                } else {
                    ObservedEvent::Exec(e)
                }
            }
            wire::EXIT => ObservedEvent::Exit(ExitEvent {
                pid: raw.pid,
                uid: raw.uid,
                comm,
            }),
            wire::OPEN | wire::READ | wire::WRITE | wire::MMAP | wire::UNLINK => {
                let mut path = collector::cstr(&raw.path);
                if path.is_empty() {
                    if raw.kind == wire::OPEN && raw.dirfd != -1 {
                        let dirfd = if raw.dirfd == -100 {
                            "AT_FDCWD".to_string()
                        } else {
                            raw.dirfd.to_string()
                        };
                        let cwd = p
                            .cwd
                            .as_deref()
                            .filter(|cwd| !cwd.is_empty())
                            .map(|cwd| format!(":cwd={cwd}"))
                            .unwrap_or_default();
                        path = format!("unresolved:pid={}:dirfd={dirfd}{cwd}", raw.pid);
                    } else {
                        path = format!("unresolved:pid={}:fd={}", raw.pid, raw.fd);
                    }
                }
                if raw.path_resolution == wire::PATH_UNRESOLVED && raw.file_inode != 0 {
                    path.push_str(&format!(":inode={}:dev={}", raw.file_inode, raw.file_dev));
                }
                if raw.path_resolution == wire::PATH_KERNEL {
                    path = normalize_path(&path);
                }
                let file = FileEvent {
                    pid: raw.pid,
                    uid: raw.uid,
                    comm,
                    path,
                    kind: file_kind,
                    bytes: (raw.result >= 0 && matches!(raw.kind, wire::WRITE | wire::MMAP))
                        .then_some(raw.count),
                    count: (raw.result >= 0 && matches!(raw.kind, wire::WRITE | wire::MMAP))
                        .then_some(1),
                };
                match raw.kind {
                    wire::READ => ObservedEvent::FileRead(file),
                    wire::WRITE | wire::MMAP => ObservedEvent::FileWrite(file),
                    wire::UNLINK => ObservedEvent::FileUnlink(file),
                    _ => ObservedEvent::FileOpen(file),
                }
            }
            wire::RENAME => ObservedEvent::FileRename(RenameEvent {
                pid: raw.pid,
                uid: raw.uid,
                comm,
                from_path: resolved_name(&raw.path, raw.path_resolution),
                to_path: resolved_name(&raw.path2, raw.path2_resolution),
            }),
            wire::CONNECT | wire::LISTEN | wire::ACCEPT => {
                let mut net = NetEvent {
                    pid: raw.pid,
                    uid: raw.uid,
                    comm,
                    family: raw.family,
                    addr: if raw.kind == wire::LISTEN {
                        raw.local_addr
                    } else {
                        raw.addr
                    },
                    local_port: raw.local_port as u16,
                    remote_port: raw.remote_port as u16,
                    hostname: None,
                    fd: (raw.kind == wire::ACCEPT).then_some(raw.fd),
                };
                if raw.kind == wire::ACCEPT {
                    let endpoint = if raw.family == 0 || raw.local_port == 0 {
                        enrich::accepted_socket(raw.pid, raw.fd)
                    } else {
                        None
                    };
                    if net.local_port == 0 {
                        net.local_port = enrich::listener_port(raw.pid, raw.flags)
                            .or_else(|| endpoint.as_ref().map(|e| e.local_port))
                            .unwrap_or(0);
                    }
                    if net.family == 0 {
                        if let Some(e) = endpoint {
                            net.family = e.family;
                            net.addr = e.remote_addr;
                            net.remote_port = e.remote_port;
                        } else {
                            return;
                        }
                    }
                }
                if let Some(ip) = dns::ip_from_addr(net.family, net.addr) {
                    net.hostname = self.dns.lookup(ip);
                }
                match raw.kind {
                    wire::CONNECT => ObservedEvent::Connect(net),
                    wire::LISTEN => ObservedEvent::Listen(net),
                    _ => ObservedEvent::Accept(net),
                }
            }
            wire::SENT | wire::RECEIVED => ObservedEvent::Traffic(TrafficSummary {
                pid: raw.pid,
                comm,
                sent: if raw.kind == wire::SENT { raw.count } else { 0 },
                recv: if raw.kind == wire::RECEIVED {
                    raw.count
                } else {
                    0
                },
            }),
            _ => return,
        };
        let entry = self.entry(&raw, event);
        if self.correlation.needs_flush() {
            self.flush_summaries();
        }
        self.correlation.observe(&entry, Some(&p));
        if raw.result < 0 {
            self.emit(entry, true, false);
            return;
        }
        if matches!(raw.kind, wire::WRITE | wire::MMAP) {
            // Detection uses the original event time, before display aggregation.
            self.analyze(&entry);
            if self.write_window.len() >= self.config.limits.window_entries {
                self.flush_write_window();
            }
            let ObservedEvent::FileWrite(file) = &entry.event else {
                unreachable!()
            };
            let key = WriteKey {
                process: entry.process.clone().unwrap(),
                exec_id: raw.exec_id,
                exe: entry.exe.clone(),
                path: file.path.clone(),
                kind: file.kind,
            };
            let stat = self.write_window.entry(key).or_insert_with(|| WriteStat {
                entry,
                count: 0,
                bytes: 0,
            });
            stat.count += 1;
            stat.bytes = stat.bytes.saturating_add(raw.count);
        } else if matches!(raw.kind, wire::SENT | wire::RECEIVED) {
            if self.traffic_window.len() >= self.config.limits.window_entries {
                self.flush_traffic_window();
            }
            let key = TrafficKey {
                process: entry.process.clone().unwrap(),
                exec_id: raw.exec_id,
                exe: entry.exe.clone(),
            };
            let stat = self
                .traffic_window
                .entry(key)
                .or_insert_with(|| TrafficStat {
                    entry,
                    sent: 0,
                    recv: 0,
                });
            if raw.kind == wire::SENT {
                stat.sent = stat.sent.saturating_add(raw.count);
            } else {
                stat.recv = stat.recv.saturating_add(raw.count);
            }
        } else {
            self.emit(entry, true, true);
        }
    }
    fn flush_summaries(&mut self) {
        for summary in self.correlation.drain() {
            self.state.lock().unwrap().record_document(
                "summaries",
                &summary.id,
                summary.last_ms,
                &summary,
            );
            if let Some(store) = &self.store {
                store.document("summaries", &summary.id, summary.last_ms, &summary);
            }
        }
    }
    fn flush_write_window(&mut self) {
        let mut writes: Vec<_> = self.write_window.drain().map(|(_, v)| v).collect();
        writes.sort_by_key(|s| std::cmp::Reverse(s.bytes));
        for (rank, mut stat) in writes.into_iter().enumerate() {
            if let ObservedEvent::FileWrite(file) = &mut stat.entry.event {
                file.bytes = Some(stat.bytes);
                file.count = Some(stat.count);
            }
            self.emit(stat.entry, rank < self.config.limits.write_top, false);
        }
    }
    fn flush_traffic_window(&mut self) {
        let mut totals: Vec<_> = self.traffic_window.drain().map(|(_, v)| v).collect();
        totals.sort_by_key(|s| std::cmp::Reverse(s.sent.saturating_add(s.recv)));
        for (rank, mut stat) in totals.into_iter().enumerate() {
            if let ObservedEvent::Traffic(summary) = &mut stat.entry.event {
                summary.sent = stat.sent;
                summary.recv = stat.recv;
            }
            self.emit(stat.entry, rank < self.config.limits.traffic_top, false);
        }
    }
}
fn resolved_name(bytes: &[u8], resolution: u32) -> String {
    let name = collector::cstr(bytes);
    if resolution == wire::PATH_KERNEL {
        normalize_path(&name)
    } else {
        name
    }
}
fn normalize_path(path: &str) -> String {
    if !path.starts_with('/') {
        return path.into();
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}
fn boot_wall_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
    }
    api::now_ms().saturating_sub(ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000)
}

fn run() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    install_signal_handlers();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!(
            "electric-eyed — kernel activity monitor\n\nUSAGE: electric-eyed [--stdout] [--json] [--no-bpf] [--no-socket] [--no-mcp] [--no-db] [--socket <path>] [--mcp-socket <path>] [--mcp-tools <default|all|list>] [--db <path>] [--config <path>] [--ebpf-object <path>] [--check-config]\n\nThe read-only query API and MCP server use Unix sockets under /run/electric-eye by default. Use --no-socket or --no-mcp to disable either. Connect MCP clients through: electric-eye mcp\n\nUse --print-default-config to print every supported setting.\nConfiguration: ~/.config/electriceye/config.toml (TOML), --config or ELECTRIC_EYE_CONFIG; system fallback /etc/electric-eye/config.toml.\nLive queries remain available with --no-db; restart history requires SQLite."
        );
        return ExitCode::SUCCESS;
    }
    if args == ["--print-default-config"] {
        println!(
            "{}",
            toml::to_string_pretty(&config::Config::default()).expect("serializing default TOML")
        );
        return ExitCode::SUCCESS;
    }
    if args == ["--version"] {
        println!("electric-eyed {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("electric-eyed - kernel activity monitor");
            eprintln!();
            eprintln!(
                "USAGE: sudo electric-eyed [--stdout] [--json] [--no-bpf] \
                 [--no-socket] [--no-mcp] [--no-db] [--socket <path>] \
                 [--mcp-socket <path>] [--db <path>] [--config <path>] \
                 [--ebpf-object <path>] [--check-config]"
            );
            eprintln!();
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    let config_path = config::Config::discover(options.config.clone());
    let config = match config_path.as_deref().map(config::Config::load).transpose() {
        Ok(config) => config.unwrap_or_default(),
        Err(err) => {
            eprintln!("configuration error: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    if options.check_config {
        match config_path.as_deref() {
            Some(path) => println!("configuration valid: {}", path.display()),
            None => println!("configuration valid: built-in defaults"),
        }
        return ExitCode::SUCCESS;
    }
    print_banner(options.json);
    if let Some(path) = &config_path {
        startup_line(options.json, format!("configuration: {}", path.display()));
    }
    if options.stdout {
        log::debug!("stdout mode requested");
    }

    if options.no_bpf {
        startup_line(
            options.json,
            "--no-bpf requested, exiting after startup checks",
        );
        return ExitCode::SUCCESS;
    }

    if !probe::can_load_bpf() {
        eprintln!();
        eprintln!(
            "error: loading the eBPF collector requires root or \
             CAP_BPF+CAP_PERFMON (plus read access to tracefs)."
        );
        eprintln!("run me with: sudo cargo run -p electric-eyed -- --stdout");
        return ExitCode::FAILURE;
    }

    let socket_path = socket_path(options.socket.as_deref());
    let socket = if options.no_socket {
        None
    } else {
        match api::bind_socket(&socket_path) {
            Ok(socket) => {
                startup_line(options.json, format!("socket: {}", socket_path.display()));
                Some(socket)
            }
            Err(err) => {
                eprintln!();
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        }
    };
    let mcp_socket_path = mcp_socket_path(options.mcp_socket.as_deref());
    let mcp_socket = if options.no_mcp {
        startup_line(options.json, "MCP server: disabled");
        None
    } else {
        match mcp::bind_socket(&mcp_socket_path) {
            Ok(socket) => {
                startup_line(
                    options.json,
                    format!("MCP socket: {}", mcp_socket_path.display()),
                );
                Some(socket)
            }
            Err(err) => {
                eprintln!();
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        }
    };

    let object = ebpf_object_path(options.object_override.as_deref());
    if !object.exists() {
        eprintln!();
        eprintln!("error: eBPF object not found at {}", object.display());
        eprintln!("build it first with: just build-ebpf  (or: cargo xtask build-ebpf)");
        return ExitCode::FAILURE;
    }

    let database = database_path(options.db.as_deref(), options.no_db);
    let store = match database.as_deref() {
        Some(path) => match store::Store::open_with_config(path, config.clone()) {
            Ok(store) => {
                startup_line(options.json, format!("database: {}", path.display()));
                Some(store)
            }
            Err(err) => {
                eprintln!("warning: SQLite persistence disabled: {err:#}");
                None
            }
        },
        None => None,
    };

    let provenance = provenance::Provider::start();
    let groups = grouping::Groups::load(&config.limits);
    if config.journal.enabled {
        journald::startup(
            &probe::kernel_release(),
            database.as_deref().and_then(|path| path.to_str()),
        );
    }

    let state = Arc::new(Mutex::new(api::SharedState::with_config(config.clone())));
    let store_client = store.as_ref().map(|store| store.client());
    {
        let mut state = state.lock().unwrap();
        state.set_store(store_client.clone());
        state.set_mcp_socket(
            mcp_socket
                .as_ref()
                .map(|_| mcp_socket_path.display().to_string()),
        );
    }

    let baseline = store_client
        .as_ref()
        .and_then(|client| match client.baseline() {
            Ok(baseline) => Some(baseline),
            Err(err) => {
                log::warn!("could not load baseline: {err:#}");
                None
            }
        })
        .unwrap_or_default();
    let allowlist = rules::Allowlist::load(&config.rules);

    let api_server = match socket {
        Some(socket) => match api::ApiServer::start(socket, Arc::clone(&state)) {
            Ok(server) => Some(server),
            Err(err) => {
                eprintln!("error starting API: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let tool_profile = match options.mcp_tools.as_deref() {
        Some(value) => mcp::ToolProfile::parse(value),
        None => mcp::ToolProfile::from_config(&config.mcp_tools),
    };
    let tool_profile = match tool_profile {
        Ok(profile) => profile,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mcp_server = match mcp_socket {
        Some(socket) => match mcp::Server::start(socket, Arc::clone(&state), tool_profile) {
            Ok(server) => Some(server),
            Err(err) => {
                eprintln!("error starting MCP server: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let incident_worker = match config
        .journal
        .enabled
        .then(|| {
            journald::IncidentWorker::configured(
                Arc::clone(&state),
                store_client.clone(),
                config.journal.clone(),
            )
        })
        .transpose()
    {
        Ok(worker) => worker,
        Err(err) => {
            eprintln!("error starting incident worker: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut session = Session {
        registry: ProvenanceRegistry::new(),
        write_window: HashMap::new(),
        traffic_window: HashMap::new(),
        dns: dns::DnsCache::with_limits(&config.limits),
        anomalies: rules::AnomalyEngine::configured(baseline, allowlist, config.rules.clone()),
        store: store_client,
        incidents: incident_worker,
        json: options.json,
        state: Arc::clone(&state),
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_default()
            .trim()
            .into(),
        boot_wall_ms: boot_wall_ms(),
        processes: process::Registry::with_limits(&config.limits),
        config: config.clone(),
        provenance: Some(provenance),
        groups,
        flows: flows::Tracker::with_limits(&config.limits),
        correlation: correlation::Engine::configured(&config),
        udp_peers: cache::Recent::new(config.limits.flow_entries),
    };
    let mut inventory = session
        .processes
        .inventory(&session.boot_id, &session.config);
    // Parents normally predate their children. Group this explicit inventory
    // before capture so already-running applications have useful metadata too.
    inventory.sort_by_key(|p| p.identity.start_ns);
    for mut p in inventory {
        if let (Some(provider), Some(exe)) = (&session.provenance, &p.executable) {
            p.package = Some(provider.identify(exe));
            session
                .processes
                .set_package(&p.identity, p.package.clone());
        }
        let parent = p.parent.as_ref().and_then(|id| session.processes.get(id));
        let app = session.groups.assign(&p, parent, &session.config);
        session.processes.set_application(&p.identity, app.clone());
        p.application = Some(app.clone());
        session.state.lock().unwrap().record_process(p.clone());
        if let Some(group) = session.groups.applications.get(&app.task_id) {
            session.state.lock().unwrap().record_document(
                "applications",
                &app.task_id,
                p.last_seen_ms,
                group,
            );
        }
        if let Some(store) = &session.store {
            store.document("processes", &p.id, p.last_seen_ms, &p);
            if let Some(group) = session.groups.applications.get(&app.task_id) {
                store.document("applications", &app.task_id, p.last_seen_ms, group);
            }
        }
    }
    let (mut collector, report) = match Collector::load(&object, &config) {
        Ok(result) => result,
        Err(err) => {
            eprintln!();
            eprintln!("error: {err:#}");
            return ExitCode::FAILURE;
        }
    };
    for warning in &report.skipped {
        log::warn!("probe skipped: {warning}");
        eprintln!("note: probe skipped - {warning}");
    }
    startup_line(
        options.json,
        format!("attached probes: {}", report.attached.join(", ")),
    );
    {
        let mut state = state.lock().unwrap();
        state.set_probes(report.attached.clone(), report.skipped.clone());
    }

    startup_line(options.json, "streaming events:");
    let mut last_traffic = Instant::now();

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        let drained = collector
            .drain_once(&mut |event| session.handle(event))
            .unwrap_or_else(|err| {
                log::warn!("event drain failed: {err:#}");
                0
            });
        session.dns.poll();
        session.anomalies.prune(api::now_ms());
        if last_traffic.elapsed() >= Duration::from_millis(session.config.limits.aggregation_ms) {
            last_traffic = Instant::now();
            session.flush_traffic_window();
            state
                .lock()
                .unwrap()
                .set_capture_loss(collector.loss_counts());
            session.flush_write_window();
            session.flush_summaries();
        }
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(session.config.limits.idle_sleep_ms));
        }
    }
    session.flush_write_window();
    session.flush_traffic_window();
    session.flush_summaries();
    drop(mcp_server);
    drop(api_server);
    session.incidents.take();
    if let Some(store) = store {
        store.shutdown();
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(items: &[&str]) -> Options {
        let args: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        Options::parse(&args).expect("valid arguments")
    }

    #[test]
    fn accepts_stdout_flag() {
        assert!(opts(&["--stdout"]).stdout);
        assert!(!opts(&[]).stdout);
    }

    #[test]
    fn accepts_json_and_socket_flags() {
        let parsed = opts(&["--json", "--no-socket", "--socket", "/tmp/ee.sock"]);
        assert!(parsed.json);
        assert!(parsed.no_socket);
        assert_eq!(parsed.socket, Some(PathBuf::from("/tmp/ee.sock")));
    }

    #[test]
    fn accepts_no_bpf_flag() {
        assert!(opts(&["--no-bpf"]).no_bpf);
    }

    #[test]
    fn accepts_check_config_flag() {
        assert!(opts(&["--check-config"]).check_config);
        assert!(!opts(&[]).check_config);
    }

    #[test]
    fn accepts_mcp_flags() {
        let parsed = opts(&["--no-mcp", "--mcp-socket", "/tmp/ee-mcp.sock"]);
        assert!(parsed.no_mcp);
        assert_eq!(parsed.mcp_socket, Some(PathBuf::from("/tmp/ee-mcp.sock")));
        assert!(!opts(&[]).no_mcp);
        assert_eq!(
            opts(&["--mcp-tools", "all"]).mcp_tools.as_deref(),
            Some("all")
        );
    }

    #[test]
    fn parses_ebpf_object_override() {
        let parsed = opts(&["--ebpf-object", "/tmp/foo.o"]);
        assert_eq!(parsed.object_override, Some(PathBuf::from("/tmp/foo.o")));
    }

    #[test]
    fn rejects_unknown_flags() {
        let args: Vec<String> = vec!["--bogus".into()];
        assert!(Options::parse(&args).is_err());
    }

    #[test]
    fn classifies_open_flags() {
        assert_eq!(classify_open(0o1), FileKind::Open);
        assert_eq!(classify_open(0o1 | 0o100), FileKind::Create);
        assert_eq!(classify_open(0o1 | 0o100 | 0o1000), FileKind::Truncate);
        assert_eq!(classify_open(0o2 | 0o1000), FileKind::Truncate);
    }

    #[test]
    fn env_overrides_are_only_fallbacks() {
        let parsed = opts(&["--socket", "/tmp/explicit.sock"]);
        assert_eq!(
            socket_path(parsed.socket.as_deref()),
            PathBuf::from("/tmp/explicit.sock")
        );
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    fn session(store: Option<store::StoreClient>) -> Session {
        Session {
            registry: ProvenanceRegistry::new(),
            write_window: HashMap::new(),
            traffic_window: HashMap::new(),
            dns: dns::DnsCache::new(),
            anomalies: rules::AnomalyEngine::new(),
            store,
            incidents: None,
            json: true,
            state: Arc::new(Mutex::new(api::SharedState::new())),
            boot_id: "test-boot".into(),
            boot_wall_ms: 1_000_000,
            processes: process::Registry::default(),
            config: config::Config::default(),
            provenance: None,
            groups: grouping::Groups::default(),
            flows: flows::Tracker::default(),
            correlation: correlation::Engine::default(),
            udp_peers: cache::Recent::new(config::Limits::default().flow_entries),
        }
    }
    fn record(kind: u32, pid: u32, start: u64, path: &str) -> wire::Record {
        let mut r = wire::Record::ZERO;
        r.kind = kind;
        r.pid = pid;
        r.uid = 1000;
        r.start_ns = start;
        r.ts_ns = 1_000_000_000;
        r.count = 1;
        r.path_resolution = wire::PATH_KERNEL;
        r.comm[..8].copy_from_slice(b"test-app");
        r.exe[..13].copy_from_slice(b"/opt/test-app");
        r.path[..path.len()].copy_from_slice(path.as_bytes());
        r
    }
    #[test]
    fn all_writes_reach_history_and_sqlite_beyond_display_top() {
        let temp = tempfile::tempdir().unwrap();
        let store = store::Store::open(&temp.path().join("test.db")).unwrap();
        let client = store.client();
        let mut s = session(Some(client.clone()));
        for i in 0..40 {
            s.handle(record(
                wire::WRITE,
                4_000_000_000,
                1,
                &format!("/home/review/Documents/file-{i}"),
            ));
        }
        s.flush_write_window();
        assert_eq!(
            s.state.lock().unwrap().activity_value(100)["activity"]
                .as_array()
                .unwrap()
                .len(),
            40
        );
        store.shutdown();
        for i in 0..40 {
            assert_eq!(
                client
                    .why(&format!("/home/review/Documents/file-{i}"), 10)
                    .unwrap()["events"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    #[test]
    fn all_traffic_reaches_history_and_deltas_add() {
        let mut s = session(None);
        for pid in 4_000_000_000..4_000_000_020 {
            for _ in 0..3 {
                s.handle(record(wire::SENT, pid, 1, ""));
            }
        }
        s.flush_traffic_window();
        let v = s.state.lock().unwrap().activity_value(100);
        assert_eq!(v["activity"].as_array().unwrap().len(), 20);
        assert!(
            v["activity"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["event"]["sent"] == 3)
        );
    }
    #[test]
    fn exit_and_pid_reuse_do_not_change_pending_write_actor() {
        let mut s = session(None);
        let old = record(wire::WRITE, 4_000_000_000, 1, "/home/review/file");
        s.handle(old);
        s.handle(record(wire::EXIT, old.pid, 1, ""));
        let mut new = record(wire::WRITE, old.pid, 2, "/home/review/file");
        new.exe.fill(0);
        new.exe[..12].copy_from_slice(b"/opt/new-app");
        s.handle(new);
        s.flush_write_window();
        let v = s.state.lock().unwrap().activity_value(10);
        let writes: Vec<_> = v["activity"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event"]["event"] == "file_write")
            .collect();
        assert_eq!(writes.len(), 2);
        assert!(
            writes
                .iter()
                .any(|e| e["process"]["start_ns"] == 1 && e["exe"] == "/opt/test-app")
        );
        assert!(
            writes
                .iter()
                .any(|e| e["process"]["start_ns"] == 2 && e["exe"] == "/opt/new-app")
        );
    }
    #[test]
    fn same_process_exec_generations_do_not_merge_writes() {
        let mut s = session(None);
        let old = record(wire::WRITE, 4_000_000_000, 1, "/home/review/file");
        s.handle(old);
        let mut new = old;
        new.exe[5] = b'n';
        s.handle(new);
        s.flush_write_window();
        assert_eq!(
            s.state.lock().unwrap().activity_value(10)["activity"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn unresolved_path_is_visible_without_becoming_a_sensitive_incident() {
        let mut s = session(None);
        let mut r = record(wire::WRITE, 4_000_000_000, 1, "/root/.ssh/key");
        r.path_resolution = wire::PATH_UNRESOLVED;
        s.handle(r);
        s.flush_write_window();
        let state = s.state.lock().unwrap();
        assert!(state.recent_incidents(10).is_empty());
        assert_eq!(
            state.activity_value(10)["activity"][0]["path_resolution"],
            "unresolved"
        );
    }
    #[test]
    fn lexical_paths_do_not_assume_symlink_parent_components() {
        let mut s = session(None);
        let mut r = record(wire::WRITE, 4_000_000_000, 1, "/home/review/link/../secret");
        r.path_resolution = wire::PATH_LEXICAL;
        s.handle(r);
        s.flush_write_window();
        assert_eq!(
            s.state.lock().unwrap().activity_value(10)["activity"][0]["event"]["path"],
            "/home/review/link/../secret"
        );
    }
    #[test]
    fn failed_writes_remain_attempts_without_bytes_or_baseline_learning() {
        let temp = tempfile::tempdir().unwrap();
        let store = store::Store::open(&temp.path().join("test.db")).unwrap();
        let client = store.client();
        let mut s = session(Some(client.clone()));
        let mut r = record(wire::WRITE, 4_000_000_000, 1, "/root/.ssh/test-key");
        r.result = -libc::EACCES as i64;
        s.handle(r);
        assert!(s.write_window.is_empty());
        assert!(s.state.lock().unwrap().recent_incidents(10).is_empty());
        store.shutdown();
        let rows = client.why("/root/.ssh/test-key", 10).unwrap();
        assert_eq!(rows["events"][0]["kind"], "file.write.attempt");
        assert!(rows["events"][0]["bytes"].is_null());
        assert_eq!(rows["events"][0]["entry"]["syscall_result"], -libc::EACCES);
        assert!(
            !client
                .baseline()
                .unwrap()
                .knows_path("/opt/test-app", "/root/.ssh/test-key")
        );
    }
    #[test]
    fn exclusions_use_path_boundaries_and_keep_crossing_renames() {
        let mut s = session(None);
        s.config.ignore_paths.push("/private".into());
        s.handle(record(wire::WRITE, 4_000_000_000, 1, "/private/ignored"));
        assert!(s.write_window.is_empty());
        s.handle(record(
            wire::WRITE,
            4_000_000_000,
            1,
            "/private-other/visible",
        ));
        assert_eq!(s.write_window.len(), 1);
        let mut rename = record(wire::RENAME, 4_000_000_000, 1, "/private/from");
        rename.path2[..11].copy_from_slice(b"/public/out");
        rename.path2_resolution = wire::PATH_KERNEL;
        s.handle(rename);
        assert_eq!(
            s.state.lock().unwrap().activity_value(10)["activity"][0]["event"]["to_path"],
            "/public/out"
        );
    }
    #[test]
    fn failed_openat_without_a_path_retains_dirfd_context() {
        let mut s = session(None);
        let mut r = record(wire::OPEN, 4_000_000_000, 1, "");
        r.flags = 0o1;
        r.dirfd = -100;
        r.result = -libc::ENXIO as i64;
        r.path_resolution = wire::PATH_UNRESOLVED;
        s.handle(r);
        let value = s.state.lock().unwrap().activity_value(10);
        let path = value["activity"][0]["event"]["path"].as_str().unwrap();
        assert!(
            path.starts_with("unresolved:pid=4000000000:dirfd=AT_FDCWD"),
            "{path}"
        );
        assert_eq!(value["activity"][0]["path_resolution"], "unresolved");
    }

    #[test]
    fn pathless_fd_events_keep_inode_and_device_identity() {
        let mut s = session(None);
        let mut r = record(wire::MMAP, 4_000_000_000, 1, "");
        r.result = 0;
        r.count = 4096;
        r.file_inode = 1234;
        r.file_dev = 5678;
        r.path_resolution = wire::PATH_UNRESOLVED;
        s.handle(r);
        s.flush_write_window();
        let value = s.state.lock().unwrap().activity_value(10);
        let path = value["activity"][0]["event"]["path"].as_str().unwrap();
        assert!(path.contains("inode=1234"), "{path}");
        assert!(path.contains("dev=5678"), "{path}");
        assert_eq!(value["activity"][0]["path_resolution"], "unresolved");
    }

    #[test]
    fn review_same_binary_reexec_keeps_write_and_traffic_generations_separate() {
        let mut s = session(None);
        let mut first = record(wire::WRITE, 4_000_000_000, 1, "/home/review/file");
        first.exec_id = 1;
        let mut second = first;
        second.exec_id = 2;
        s.handle(first);
        let mut sent = first;
        sent.kind = wire::SENT;
        sent.count = 3;
        s.handle(sent);
        let mut exec = second;
        exec.kind = wire::EXEC;
        s.handle(exec);
        s.handle(second);
        sent.exec_id = 2;
        sent.count = 5;
        s.handle(sent);
        s.flush_write_window();
        s.flush_traffic_window();
        let activity = s.state.lock().unwrap().activity_value(10);
        let writes: Vec<_> = activity["activity"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["event"]["event"] == "file_write")
            .collect();
        assert_eq!(
            writes.len(),
            2,
            "writes across exec generations were merged: {activity}"
        );

        let traffic: Vec<_> = activity["activity"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event"]["event"] == "traffic")
            .collect();
        assert_eq!(traffic.len(), 2);
        assert!(traffic.iter().any(|e| {
            e["event"]["sent"] == 3
                && e["application"]["task_id"]
                    .as_str()
                    .unwrap()
                    .ends_with("exec:1")
        }));
        assert!(traffic.iter().any(|e| {
            e["event"]["sent"] == 5
                && e["application"]["task_id"]
                    .as_str()
                    .unwrap()
                    .ends_with("exec:2")
        }));
    }

    #[test]
    fn udp_connect_and_sendto_feed_history_and_egress_rules_without_duplicate_destinations() {
        let mut s = session(None);
        s.handle(record(
            wire::READ,
            4_000_000_000,
            1,
            "/home/review/.ssh/key",
        ));
        let mut net = record(wire::NET_RESULT, 4_000_000_000, 1, "");
        net.protocol = 17;
        net.family = 2;
        net.socket_id = 10;
        net.addr[..4].copy_from_slice(&[8, 8, 8, 8]);
        net.remote_port = 53;
        s.handle(net);
        assert!(
            s.state
                .lock()
                .unwrap()
                .recent_incidents(10)
                .iter()
                .any(|i| i["details"]["rule"] == "sensitive_egress")
        );
        let before = s.state.lock().unwrap().activity_value(100)["activity"]
            .as_array()
            .unwrap()
            .len();
        net.kind = wire::SENT;
        net.count = 4;
        s.handle(net);
        assert_eq!(
            s.state.lock().unwrap().activity_value(100)["activity"]
                .as_array()
                .unwrap()
                .len(),
            before
        );
        net.addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        s.handle(net);
        let activity = s.state.lock().unwrap().activity_value(100);
        assert_eq!(
            activity["activity"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["event"]["event"] == "connect")
                .count(),
            2
        );
    }

    #[test]
    fn udp_novel_destination_rule_obeys_configured_baseline_threshold_and_switch() {
        for enabled in [true, false] {
            let mut s = session(None);
            s.anomalies = rules::AnomalyEngine::configured(
                rules::BaselineData::from_pairs(
                    Vec::new(),
                    vec![("/opt/test-app".into(), "1.1.1.1:443".into())],
                ),
                rules::Allowlist::default(),
                config::RuleConfig {
                    novel_network: enabled,
                    novel_network_min_destinations: 1,
                    ..Default::default()
                },
            );
            let mut net = record(wire::SENT, 4_000_000_000, 1, "");
            net.protocol = 17;
            net.family = 2;
            net.socket_id = 7;
            net.addr[..4].copy_from_slice(&[8, 8, 8, 8]);
            net.remote_port = 53;
            s.handle(net);
            assert_eq!(
                s.state
                    .lock()
                    .unwrap()
                    .recent_incidents(10)
                    .iter()
                    .any(|i| i["details"]["rule"] == "novel_network"),
                enabled
            );
        }
    }
}
