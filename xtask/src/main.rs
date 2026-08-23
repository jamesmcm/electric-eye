mod build_ebpf;

use std::process::ExitCode;

use anyhow::Result;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    let project_root = project_root();
    match args.first().map(String::as_str) {
        Some("build-ebpf") => build_ebpf::build(&project_root),
        _ => {
            eprintln!("USAGE: cargo xtask <TASK>");
            eprintln!();
            eprintln!("TASKS:");
            eprintln!("  build-ebpf    build the eBPF object with the nightly toolchain");
            Ok(())
        }
    }
}

fn project_root() -> std::path::PathBuf {
    std::path::Path::new(&std::env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .expect("xtask lives inside the project")
        .to_path_buf()
}
