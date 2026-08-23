mod collector;
mod enrich;
mod probe;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use collector::{Collector, RawExecEvent};
use electric_eye_core::ExecEvent;
use electric_eye_nix::ProvenanceRegistry;

const DEFAULT_OBJECT: &str = "target/bpfel-unknown-none/release/electric-eye-ebpf";

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

fn print_exec(event: &RawExecEvent, registry: &ProvenanceRegistry) {
    let exe = enrich::resolve_exe(event.pid)
        .or_else(|| enrich::argv0(event.pid).map(PathBuf::from))
        .unwrap_or_else(|| "(exited)".into());

    let stat = enrich::process_stat(event.pid);

    let exec = ExecEvent {
        pid: event.pid,
        ppid: stat.map(|s| s.ppid).unwrap_or(event.ppid),
        uid: event.uid,
        comm: event.comm_str(),
        exe,
    };

    let mut line = format!("{exec}");

    if let Some(unit) = enrich::systemd_unit(event.pid) {
        line.push_str(&format!("  [{unit}]"));
    }

    if let Ok(Some(provenance)) = registry.identify(exec.exe.as_path()) {
        line.push_str(&format!("  (nix: {provenance})"));
    }

    println!("{line}");
}

fn main() -> ExitCode {
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

    let registry = ProvenanceRegistry::new();

    let mut collector = match Collector::load(&object) {
        Ok(collector) => collector,
        Err(err) => {
            eprintln!();
            eprintln!("error: {err:#}");
            return ExitCode::FAILURE;
        }
    };

    println!("attached sched_process_exec; streaming events:");
    collector.poll_forever(|event| print_exec(&event, &registry));
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
