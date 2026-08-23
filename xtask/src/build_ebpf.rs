use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

const EBPF_CRATE: &str = "electric-eye-ebpf";
const BPF_TARGET: &str = "bpfel-unknown-none";

pub fn build(project_root: &Path) -> Result<()> {
    let ebpf_dir = project_root.join("crates").join(EBPF_CRATE);
    let target_dir = project_root.join("target").join(BPF_TARGET);

    ensure_nightly()?;

    let status = Command::new("rustup")
        .args(["run", "nightly", "cargo"])
        .arg("build")
        .arg(format!("--target={BPF_TARGET}"))
        .args(["-Z", "build-std=core", "--release"])
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&ebpf_dir)
        .status()
        .context("failed to spawn rustup-managed cargo for the eBPF build")?;

    if !status.success() {
        bail!("eBPF crate build failed");
    }

    let object = target_dir.join(BPF_TARGET).join("release").join(EBPF_CRATE);
    anyhow::ensure!(
        object.exists(),
        "expected eBPF object at {}",
        object.display()
    );
    println!("built {}", object.display());
    Ok(())
}

fn ensure_nightly() -> Result<()> {
    let probe = Command::new("rustup")
        .args(["run", "nightly", "cargo", "--version"])
        .output()
        .context("failed to run rustup (is it installed?)")?;
    if !probe.status.success() {
        bail!(
            "the nightly toolchain with the rust-src component is required; \
             install it with: rustup toolchain install nightly --profile minimal --component rust-src"
        );
    }
    Ok(())
}
