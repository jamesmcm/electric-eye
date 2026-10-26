mod api;
mod collector;
mod enrich;
mod format;
mod probe;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use collector::{Collector, RawEvent};
use electric_eye_core::{
    ExecEvent, ExitEvent, FileEvent, FileKind, NetEvent, ObservedEvent, RenameEvent, TrafficSummary,
};
use electric_eye_nix::ProvenanceRegistry;

const DEFAULT_OBJECT: &str = "target/bpfel-unknown-none/release/electric-eye-ebpf";
const INSTALLED_OBJECT: &str = "/usr/lib/electric-eye/electric-eye-ebpf";
const TRAFFIC_WINDOW: Duration = Duration::from_secs(5);
const TRAFFIC_TOP: usize = 8;
const PID_CACHE_LIMIT: usize = 8192;

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
    socket: Option<PathBuf>,
    object_override: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options {
            stdout: false,
            json: false,
            no_bpf: false,
            no_socket: false,
            socket: None,
            object_override: None,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--stdout" => options.stdout = true,
                "--json" => options.json = true,
                "--no-bpf" => options.no_bpf = true,
                "--no-socket" => options.no_socket = true,
                "--socket" => {
                    let Some(value) = iter.next() else {
                        return Err("--socket requires a path".into());
                    };
                    options.socket = Some(PathBuf::from(value));
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

fn is_noise_path(path: &str) -> bool {
    ["/dev/", "/proc/", "/sys/", "/run/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn print_banner() {
    println!("electric-eyed starting");
    println!("kernel: {}", probe::kernel_release());
    println!(
        "BTF: {}",
        if probe::btf_available() {
            "available"
        } else {
            "unavailable"
        }
    );
}

struct Session {
    registry: ProvenanceRegistry,
    comm_by_pid: HashMap<u32, String>,
    cwd_by_pid: HashMap<u32, PathBuf>,
    ppid_by_pid: HashMap<u32, u32>,
    start_by_pid: HashMap<u32, u64>,
    traffic_window: HashMap<u32, (u64, u64)>,
    json: bool,
    state: Arc<Mutex<api::SharedState>>,
}

impl Session {
    fn remember_comm(&mut self, pid: u32, comm: &str) {
        if self.comm_by_pid.len() >= PID_CACHE_LIMIT {
            self.comm_by_pid.clear();
        }
        self.comm_by_pid.insert(pid, comm.to_string());
    }

    fn comm_for(&mut self, pid: u32) -> String {
        if let Some(comm) = self.comm_by_pid.get(&pid) {
            return comm.clone();
        }
        match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(comm) => {
                let comm = comm.trim().to_string();
                self.remember_comm(pid, &comm);
                comm
            }
            Err(_) => format!("pid {pid}"),
        }
    }

    fn parent_for(&mut self, pid: u32) -> Option<String> {
        let ppid = match self.ppid_by_pid.get(&pid) {
            Some(ppid) => *ppid,
            None => {
                let stat = enrich::process_stat(pid)?;
                self.ppid_by_pid.insert(pid, stat.ppid);
                stat.ppid
            }
        };
        if ppid == 0 || ppid == pid {
            return None;
        }
        Some(self.comm_for(ppid))
    }

    fn resolve_path(&mut self, pid: u32, path: &str) -> String {
        if path.starts_with('/') || path.is_empty() {
            return path.to_string();
        }
        let cwd = match self.cwd_by_pid.get(&pid) {
            Some(cwd) => cwd.clone(),
            None => {
                let Ok(cwd) = std::fs::read_link(format!("/proc/{pid}/cwd")) else {
                    return path.to_string();
                };
                self.cwd_by_pid.insert(pid, cwd.clone());
                cwd
            }
        };
        cwd.join(path).display().to_string()
    }

    fn context_for(
        &mut self,
        pid: u32,
        exe: Option<PathBuf>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let unit = enrich::systemd_unit(pid);
        let nix = exe
            .as_deref()
            .and_then(|exe| self.registry.identify(exe).ok().flatten())
            .map(|provenance| provenance.to_string());
        let parent = self.parent_for(pid);
        (unit, nix, parent)
    }

    fn emit(&mut self, observed: ObservedEvent, pid: u32, exe: Option<PathBuf>) {
        let (unit, nix, parent) = self.context_for(pid, exe);
        let entry = api::ActivityEntry {
            ts_ms: api::now_ms(),
            event: observed.clone(),
            unit,
            nix,
            parent,
        };
        if self.json {
            match serde_json::to_string(&entry) {
                Ok(line) => println!("{line}"),
                Err(err) => log::warn!("failed to serialize event: {err}"),
            }
        } else {
            let mut suffix = String::new();
            if let Some(unit) = &entry.unit {
                suffix.push_str(&format!("  [{unit}]"));
            }
            if let Some(nix) = &entry.nix {
                suffix.push_str(&format!("  (nix: {nix})"));
            }
            if let Some(parent) = &entry.parent {
                suffix.push_str(&format!("  parent={parent}"));
            }
            println!("{observed}{suffix}");
        }
        self.state.lock().unwrap().record(entry);
    }

    fn net_event(&mut self, event: &collector::RawNetEvent) -> NetEvent {
        self.remember_comm(event.pid, &event.comm_str());
        NetEvent {
            pid: event.pid,
            uid: event.uid,
            comm: event.comm_str(),
            family: event.family,
            addr: event.addr,
            local_port: event.sport as u16,
            remote_port: event.dport as u16,
        }
    }

    fn emit_file(&mut self, kind: FileKind, pid: u32, uid: u32, comm: &str, path: String) {
        let exe = enrich::resolve_exe(pid);
        let event = FileEvent {
            pid,
            uid,
            comm: comm.to_string(),
            path,
            kind,
        };
        let observed = match kind {
            FileKind::Write => ObservedEvent::FileWrite(event),
            FileKind::Unlink => ObservedEvent::FileUnlink(event),
        };
        self.emit(observed, pid, exe);
    }

    fn handle(&mut self, event: RawEvent) {
        match event {
            RawEvent::Exec(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let exe = enrich::resolve_exe(event.pid)
                    .or_else(|| enrich::argv0(event.pid).map(PathBuf::from))
                    .unwrap_or_else(|| "(exited)".into());
                let stat = enrich::process_stat(event.pid);
                let ppid = stat.map(|s| s.ppid).unwrap_or(event.ppid);
                let start_ticks = stat.map(|s| s.start_ticks).unwrap_or(0);
                self.ppid_by_pid.insert(event.pid, ppid);
                self.start_by_pid.insert(event.pid, start_ticks);
                let observed = ObservedEvent::Exec(ExecEvent {
                    pid: event.pid,
                    ppid,
                    uid: event.uid,
                    comm: event.comm_str(),
                    exe: exe.clone(),
                    start_ticks,
                });
                self.emit(observed, event.pid, Some(exe));
            }
            RawEvent::Exit(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let exe = enrich::resolve_exe(event.pid);
                let observed = ObservedEvent::Exit(ExitEvent {
                    pid: event.pid,
                    uid: event.uid,
                    comm: event.comm_str(),
                });
                self.emit(observed, event.pid, exe);
                self.comm_by_pid.remove(&event.pid);
                self.cwd_by_pid.remove(&event.pid);
                self.ppid_by_pid.remove(&event.pid);
                self.start_by_pid.remove(&event.pid);
            }
            RawEvent::Connect(event) => {
                let net = self.net_event(&event);
                let exe = enrich::resolve_exe(event.pid);
                self.emit(ObservedEvent::Connect(net), event.pid, exe);
            }
            RawEvent::Accept(event) => {
                let net = self.net_event(&event);
                let exe = enrich::resolve_exe(event.pid);
                self.emit(ObservedEvent::Accept(net), event.pid, exe);
            }
            RawEvent::Listen(event) => {
                let net = self.net_event(&event);
                let exe = enrich::resolve_exe(event.pid);
                self.emit(ObservedEvent::Listen(net), event.pid, exe);
            }
            RawEvent::FileWrite(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let path = self.resolve_path(event.pid, &event.path_str());
                if !is_noise_path(&path) {
                    self.emit_file(
                        FileKind::Write,
                        event.pid,
                        event.uid,
                        &event.comm_str(),
                        path,
                    );
                }
            }
            RawEvent::FileUnlink(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let path = self.resolve_path(event.pid, &event.path_str());
                if !is_noise_path(&path) {
                    self.emit_file(
                        FileKind::Unlink,
                        event.pid,
                        event.uid,
                        &event.comm_str(),
                        path,
                    );
                }
            }
            RawEvent::FileRename(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let exe = enrich::resolve_exe(event.pid);
                let observed = ObservedEvent::FileRename(RenameEvent {
                    pid: event.pid,
                    uid: event.uid,
                    comm: event.comm_str(),
                    from_path: self.resolve_path(event.pid, &event.old_path_str()),
                    to_path: self.resolve_path(event.pid, &event.new_path_str()),
                });
                self.emit(observed, event.pid, exe);
            }
        }
    }

    fn print_traffic_window(&mut self, collector: &mut Collector) {
        let Ok(totals) = collector.drain_net_totals() else {
            return;
        };
        for (pid, sent, recv) in totals {
            let entry = self.traffic_window.entry(pid).or_insert((0, 0));
            entry.0 += sent;
            entry.1 += recv;
        }

        let raw: Vec<(u32, u64, u64)> = self
            .traffic_window
            .iter()
            .map(|(pid, (sent, recv))| (*pid, *sent, *recv))
            .collect();
        self.traffic_window.clear();

        let mut summaries: Vec<TrafficSummary> = raw
            .into_iter()
            .map(|(pid, sent, recv)| TrafficSummary {
                pid,
                comm: self.comm_for(pid),
                sent,
                recv,
            })
            .filter(|summary| summary.total() > 0)
            .collect();

        if summaries.is_empty() {
            return;
        }
        summaries.sort_by_key(|summary| std::cmp::Reverse(summary.total()));
        for summary in summaries.into_iter().take(TRAFFIC_TOP) {
            let pid = summary.pid;
            let exe = enrich::resolve_exe(pid);
            self.emit(ObservedEvent::Traffic(summary), pid, exe);
        }
    }
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
                 [--no-socket] [--socket <path>] [--ebpf-object <path>]"
            );
            eprintln!();
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    print_banner();
    if options.stdout {
        log::debug!("stdout mode requested");
    }

    if options.no_bpf {
        println!("--no-bpf requested, exiting after startup checks");
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
                println!("socket: {}", socket_path.display());
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

    let (mut collector, report) = match Collector::load(&object) {
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
    println!("attached probes: {}", report.attached.join(", "));
    println!("streaming events:");

    let state = Arc::new(Mutex::new(api::SharedState::new()));
    state
        .lock()
        .unwrap()
        .set_probes(report.attached.clone(), report.skipped.clone());

    let mut session = Session {
        registry: ProvenanceRegistry::new(),
        comm_by_pid: HashMap::new(),
        cwd_by_pid: HashMap::new(),
        ppid_by_pid: HashMap::new(),
        start_by_pid: HashMap::new(),
        traffic_window: HashMap::new(),
        json: options.json,
        state: Arc::clone(&state),
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
        if last_traffic.elapsed() >= TRAFFIC_WINDOW {
            last_traffic = Instant::now();
            session.print_traffic_window(&mut collector);
        }
        if let Some(socket) = &socket {
            api::serve_pending(socket, &state);
        }
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
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
    fn env_overrides_are_only_fallbacks() {
        let parsed = opts(&["--socket", "/tmp/explicit.sock"]);
        assert_eq!(
            socket_path(parsed.socket.as_deref()),
            PathBuf::from("/tmp/explicit.sock")
        );
    }
}
