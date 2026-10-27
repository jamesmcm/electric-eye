mod api;
mod btf;
mod collector;
mod dns;
mod enrich;
mod format;
mod journald;
mod probe;
mod rules;
mod store;
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
const TRAFFIC_WINDOW: Duration = Duration::from_secs(5);
const TRAFFIC_TOP: usize = 8;
const WRITE_TOP: usize = 32;
const WRITE_WINDOW_LIMIT: usize = 4096;

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
    no_db: bool,
    socket: Option<PathBuf>,
    db: Option<PathBuf>,
    object_override: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options {
            stdout: false,
            json: false,
            no_bpf: false,
            no_socket: false,
            no_db: false,
            socket: None,
            db: None,
            object_override: None,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--stdout" => options.stdout = true,
                "--json" => options.json = true,
                "--no-bpf" => options.no_bpf = true,
                "--no-socket" => options.no_socket = true,
                "--no-db" => options.no_db = true,
                "--socket" => {
                    let Some(value) = iter.next() else {
                        return Err("--socket requires a path".into());
                    };
                    options.socket = Some(PathBuf::from(value));
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

fn is_noise_path(path: &str) -> bool {
    ["/dev/", "/proc/", "/sys/", "/run/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
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
    exe: Option<String>,
    path: String,
    kind: FileKind,
}
#[derive(Hash, PartialEq, Eq)]
struct TrafficKey {
    process: ProcessIdentity,
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
}
impl Session {
    fn entry(&mut self, raw: &wire::Record, event: ObservedEvent) -> ActivityEntry {
        let exe = collector::cstr(&raw.exe);
        let exe = (!exe.is_empty()).then_some(exe);
        // /proc enrichment is optional and is used only if its generation
        // matches the identity captured in the kernel. Executable identity
        // itself always comes from the event, including short-lived tasks.
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let same_process = enrich::process_stat(raw.pid)
            .is_some_and(|s| s.start_ticks == raw.start_ns / (1_000_000_000 / ticks));
        let unit = if same_process {
            enrich::systemd_unit(raw.pid)
        } else {
            None
        };
        let nix = exe
            .as_deref()
            .and_then(|path| self.registry.identify(Path::new(path)).ok().flatten())
            .map(|p| p.to_string());
        ActivityEntry {
            ts_ms: self.boot_wall_ms.saturating_add(raw.ts_ns / 1_000_000),
            syscall_result: matches!(
                raw.kind,
                wire::OPEN | wire::READ | wire::WRITE | wire::MMAP | wire::UNLINK | wire::RENAME
            )
            .then_some(raw.result),
            process: Some(ProcessIdentity {
                pid: raw.pid,
                start_ns: raw.start_ns,
                boot_id: self.boot_id.clone(),
            }),
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
    fn emit_incident(&mut self, incident: rules::Incident) {
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
    fn handle(&mut self, raw: wire::Record) {
        let comm = collector::cstr(&raw.comm);
        let file_kind = match raw.kind {
            wire::READ => FileKind::Read,
            wire::WRITE => FileKind::Write,
            wire::MMAP => FileKind::Mmap,
            wire::UNLINK => FileKind::Unlink,
            _ => classify_open(raw.flags),
        };
        let event = match raw.kind {
            wire::EXEC => ObservedEvent::Exec(ExecEvent {
                pid: raw.pid,
                ppid: raw.ppid,
                uid: raw.uid,
                comm,
                exe: PathBuf::from(collector::cstr(&raw.exe)),
                start_ticks: raw.start_ns
                    / (1_000_000_000 / (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64)),
            }),
            wire::EXIT => ObservedEvent::Exit(ExitEvent {
                pid: raw.pid,
                uid: raw.uid,
                comm,
            }),
            wire::OPEN | wire::READ | wire::WRITE | wire::MMAP | wire::UNLINK => {
                let mut path = collector::cstr(&raw.path);
                if path.is_empty() {
                    path = format!("unresolved:pid={}:fd={}", raw.pid, raw.fd);
                }
                if raw.path_resolution == wire::PATH_KERNEL {
                    path = normalize_path(&path);
                }
                if is_noise_path(&path) {
                    return;
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
                    addr: raw.addr,
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
        if raw.result < 0 {
            self.emit(entry, true, false);
            return;
        }
        if matches!(raw.kind, wire::WRITE | wire::MMAP) {
            // Detection uses the original event time, before display aggregation.
            self.analyze(&entry);
            if self.write_window.len() >= WRITE_WINDOW_LIMIT {
                self.flush_write_window();
            }
            let ObservedEvent::FileWrite(file) = &entry.event else {
                unreachable!()
            };
            let key = WriteKey {
                process: entry.process.clone().unwrap(),
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
            if self.traffic_window.len() >= WRITE_WINDOW_LIMIT {
                self.flush_traffic_window();
            }
            let key = TrafficKey {
                process: entry.process.clone().unwrap(),
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
    fn flush_write_window(&mut self) {
        let mut writes: Vec<_> = self.write_window.drain().map(|(_, v)| v).collect();
        writes.sort_by_key(|s| std::cmp::Reverse(s.bytes));
        for (rank, mut stat) in writes.into_iter().enumerate() {
            if let ObservedEvent::FileWrite(file) = &mut stat.entry.event {
                file.bytes = Some(stat.bytes);
                file.count = Some(stat.count);
            }
            self.emit(stat.entry, rank < WRITE_TOP, false);
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
            self.emit(stat.entry, rank < TRAFFIC_TOP, false);
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
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("electric-eyed - kernel activity monitor");
            eprintln!();
            eprintln!(
                "USAGE: sudo electric-eyed [--stdout] [--json] [--no-bpf] \
                 [--no-socket] [--no-db] [--socket <path>] [--db <path>] \
                 [--ebpf-object <path>]"
            );
            eprintln!();
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    print_banner(options.json);
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

    let object = ebpf_object_path(options.object_override.as_deref());
    if !object.exists() {
        eprintln!();
        eprintln!("error: eBPF object not found at {}", object.display());
        eprintln!("build it first with: just build-ebpf  (or: cargo xtask build-ebpf)");
        return ExitCode::FAILURE;
    }

    let database = database_path(options.db.as_deref(), options.no_db);
    let store = match database.as_deref() {
        Some(path) => match store::Store::open(path) {
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

    let (mut collector, report) = match Collector::load(&object) {
        Ok(result) => result,
        Err(err) => {
            eprintln!();
            eprintln!("error: {err:#}");
            return ExitCode::FAILURE;
        }
    };

    journald::startup(
        &probe::kernel_release(),
        database.as_deref().and_then(|path| path.to_str()),
    );

    for warning in &report.skipped {
        log::warn!("probe skipped: {warning}");
        eprintln!("note: probe skipped - {warning}");
    }
    startup_line(
        options.json,
        format!("attached probes: {}", report.attached.join(", ")),
    );
    startup_line(options.json, "streaming events:");

    let state = Arc::new(Mutex::new(api::SharedState::new()));
    let store_client = store.as_ref().map(|store| store.client());
    {
        let mut state = state.lock().unwrap();
        state.set_probes(report.attached.clone(), report.skipped.clone());
        state.set_store(store_client.clone());
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
    let allowlist = rules::Allowlist::load_default();

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
    let incident_worker =
        match journald::IncidentWorker::start(Arc::clone(&state), store_client.clone()) {
            Ok(worker) => Some(worker),
            Err(err) => {
                eprintln!("error starting incident worker: {err}");
                return ExitCode::FAILURE;
            }
        };
    let mut session = Session {
        registry: ProvenanceRegistry::new(),
        write_window: HashMap::new(),
        traffic_window: HashMap::new(),
        dns: dns::DnsCache::new(),
        anomalies: rules::AnomalyEngine::with_context(baseline, allowlist),
        store: store_client,
        incidents: incident_worker,
        json: options.json,
        state: Arc::clone(&state),
        boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_default()
            .trim()
            .into(),
        boot_wall_ms: boot_wall_ms(),
    };
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
        if last_traffic.elapsed() >= TRAFFIC_WINDOW {
            last_traffic = Instant::now();
            session.flush_traffic_window();
            state
                .lock()
                .unwrap()
                .set_capture_loss(collector.loss_counts());
            session.flush_write_window();
        }
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    session.flush_write_window();
    session.flush_traffic_window();
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
}
