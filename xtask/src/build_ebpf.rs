use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

const EBPF_CRATE: &str = "electric-eye-ebpf";
const BPF_TARGET: &str = "bpfel-unknown-none";
const NIGHTLY: &str = "nightly-2026-01-20";

pub fn build(project_root: &Path) -> Result<()> {
    let ebpf_dir = project_root.join("crates").join(EBPF_CRATE);
    let target_dir = project_root.join("target");

    ensure_nightly()?;
    let nightly_rustc = nightly_rustc_path()?;

    let status = Command::new("rustup")
        .args(["run", NIGHTLY, "cargo"])
        .arg("build")
        .arg(format!("--target={BPF_TARGET}"))
        .args(["-Z", "build-std=core", "--release"])
        .envs(spawn_env())
        .env("CARGO_TARGET_DIR", &target_dir)
        .env("RUSTC", &nightly_rustc)
        // bpf_loop callbacks require BTF function metadata.
        .env(
            "RUSTFLAGS",
            format!(
                "{} -C link-arg=--btf",
                std::env::var("RUSTFLAGS").unwrap_or_default()
            ),
        )
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

fn nightly_rustc_path() -> Result<std::path::PathBuf> {
    let output = Command::new("rustup")
        .args(["which", "--toolchain", NIGHTLY, "rustc"])
        .output()
        .context("failed to query rustup for the nightly rustc path")?;
    if !output.status.success() {
        bail!("unable to locate the {NIGHTLY} rustc binary");
    }
    Ok(std::path::PathBuf::from(
        String::from_utf8(output.stdout)?.trim(),
    ))
}

fn spawn_env() -> std::collections::HashMap<String, String> {
    let mut env = std::env::vars().collect::<std::collections::HashMap<_, _>>();
    if let Some(home) = std::env::var_os("HOME") {
        let cargo_bin = Path::new(&home).join(".cargo").join("bin");
        let prepend = format!("{}:", cargo_bin.display());
        env.entry("PATH".to_string()).and_modify(|path| {
            *path = format!("{prepend}{path}");
        });
    }
    env
}

fn ensure_nightly() -> Result<()> {
    let probe = Command::new("rustup")
        .args(["run", NIGHTLY, "cargo", "--version"])
        .output()
        .context("failed to run rustup (is it installed?)")?;
    if !probe.status.success() {
        bail!(
            "the pinned eBPF toolchain ({NIGHTLY}, with the rust-src component) is required; \
             install it with: rustup toolchain install {NIGHTLY} --profile minimal --component rust-src"
        );
    }
    Ok(())
}
