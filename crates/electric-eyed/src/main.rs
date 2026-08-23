mod collector;
mod enrich;
mod format;
mod probe;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use collector::{Collector, RawEvent};
use electric_eye_core::{
    FileEvent, FileKind, NetEvent, ObservedEvent, RenameEvent, TrafficSummary,
};
use electric_eye_nix::ProvenanceRegistry;

const DEFAULT_OBJECT: &str = "target/bpfel-unknown-none/release/electric-eye-ebpf";
const TRAFFIC_WINDOW: Duration = Duration::from_secs(5);
const TRAFFIC_TOP: usize = 8;
const PID_CACHE_LIMIT: usize = 8192;

#[derive(Debug)]
struct Options {
    stdout: bool,
    no_bpf: bool,
    object_override: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut options = Options {
            stdout: false,
            no_bpf: false,
            object_override: None,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--stdout" => options.stdout = true,
                "--no-bpf" => options.no_bpf = true,
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
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(DEFAULT_OBJECT)
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
    traffic_window: HashMap<u32, (u64, u64)>,
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

    fn suffix_for(&mut self, pid: u32, exe: Option<PathBuf>) -> String {
        let mut suffix = String::new();
        if let Some(unit) = enrich::systemd_unit(pid) {
            suffix.push_str(&format!("  [{unit}]"));
        }
        if let Some(exe) = exe.as_deref()
            && let Ok(Some(provenance)) = self.registry.identify(exe)
        {
            suffix.push_str(&format!("  (nix: {provenance})"));
        }
        suffix
    }

    fn handle(&mut self, event: RawEvent) {
        match event {
            RawEvent::Exec(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let exe = enrich::resolve_exe(event.pid)
                    .or_else(|| enrich::argv0(event.pid).map(PathBuf::from))
                    .unwrap_or_else(|| "(exited)".into());
                let stat = enrich::process_stat(event.pid);
                let observed = ObservedEvent::Exec(electric_eye_core::ExecEvent {
                    pid: event.pid,
                    ppid: stat.map(|s| s.ppid).unwrap_or(event.ppid),
                    uid: event.uid,
                    comm: event.comm_str(),
                    exe: exe.clone(),
                });
                let suffix = self.suffix_for(event.pid, Some(exe));
                println!("{observed}{suffix}");
            }
            RawEvent::Connect(event) => {
                let net = self.net_event(&event);
                self.emit_net(ObservedEvent::Connect(net), event.pid)
            }
            RawEvent::Listen(event) => {
                let net = self.net_event(&event);
                self.emit_net(ObservedEvent::Listen(net), event.pid)
            }
            RawEvent::FileWrite(event) => {
                self.remember_comm(event.pid, &event.comm_str());
                let path = event.path_str();
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
                let path = event.path_str();
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
                    from_path: event.old_path_str(),
                    to_path: event.new_path_str(),
                });
                let suffix = self.suffix_for(event.pid, exe);
                println!("{observed}{suffix}");
            }
        }
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

    fn emit_net(&mut self, observed: ObservedEvent, pid: u32) {
        let exe = enrich::resolve_exe(pid);
        let suffix = self.suffix_for(pid, exe);
        println!("{observed}{suffix}");
    }

    fn emit_file(&mut self, kind: FileKind, pid: u32, uid: u32, comm: &str, path: String) {
        let exe = enrich::resolve_exe(pid);
        let observed = ObservedEvent::FileWrite(FileEvent {
            pid,
            uid,
            comm: comm.to_string(),
            path,
            kind,
        });
        let suffix = self.suffix_for(pid, exe);
        println!("{observed}{suffix}");
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
            println!("{}", ObservedEvent::Traffic(summary));
        }
    }
}

fn run() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("electric-eyed - kernel activity monitor");
            eprintln!();
            eprintln!("USAGE: sudo electric-eyed [--stdout] [--no-bpf] [--ebpf-object <path>]");
            eprintln!();
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    print_banner();

    if options.no_bpf {
        println!("--no-bpf requested, exiting after startup checks");
        return ExitCode::SUCCESS;
    }

    if !probe::running_as_root() {
        eprintln!();
        eprintln!("error: loading the eBPF collector requires root or CAP_BPF+CAP_PERFMON.");
        eprintln!("run me with: sudo cargo run -p electric-eyed -- --stdout");
        return ExitCode::FAILURE;
    }

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

    let mut session = Session {
        registry: ProvenanceRegistry::new(),
        comm_by_pid: HashMap::new(),
        traffic_window: HashMap::new(),
    };
    let mut last_traffic = Instant::now();

    loop {
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
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
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
}
