//! Automatic generated-output path detection.
//!
//! Build trees and run artifacts are a large fraction of desktop file traffic,
//! but their absolute prefixes differ per project. These heuristics recognise
//! the conventional output components and return the nearest generated root so
//! it can be filtered in the kernel for the rest of the build/run.

use std::path::{Path, PathBuf};

const PROJECT_OUTPUT_COMPONENTS: &[&str] = &[
    "target",
    "build",
    "dist",
    "out",
    "output",
    "outputs",
    "artifacts",
    "generated",
    "coverage",
];

const ALWAYS_OUTPUT_COMPONENTS: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    ".gradle",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".zig-cache",
    "zig-out",
    "cmakefiles",
    ".cache",
    "cache",
    "cache2",
    "startupcache",
    "shadercache",
    "gpucache",
    "code cache",
    "service worker",
    "indexeddb",
    "trash",
    ".trash",
    "tmp",
    "temp",
    ".tmp",
    "logs",
];

const PROJECT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Makefile",
    "CMakeLists.txt",
    "meson.build",
    "go.mod",
    "build.gradle",
    "pom.xml",
    "flake.nix",
    "default.nix",
    ".git",
];

const SENSITIVE_MARKERS: &[&str] = &[
    "/.ssh/",
    "/.gnupg/",
    "/.aws/",
    "/.azure/",
    "/.kube/",
    "/.config/gh/",
    "/.password-store/",
    "/.local/share/keyrings/",
    "/.codex/",
    "/.config/opencode/",
    "/.local/share/opencode/",
    "/.hermes/",
];

fn user_writable(path: &Path) -> bool {
    ["/home/", "/tmp/", "/var/tmp/", "/mnt/", "/media/"]
        .iter()
        .any(|root| path.starts_with(root))
}

fn sensitive(path: &Path) -> bool {
    let text = path.to_string_lossy();
    SENSITIVE_MARKERS.iter().any(|marker| text.contains(marker))
}

fn project_marker(parent: &Path) -> bool {
    parent.ancestors().take(4).any(|ancestor| {
        PROJECT_MARKERS
            .iter()
            .any(|marker| ancestor.join(marker).exists())
    })
}

fn generated_component(name: &str, parent: &Path) -> bool {
    let lower = name.to_ascii_lowercase();
    if ALWAYS_OUTPUT_COMPONENTS.contains(&lower.as_str()) {
        return true;
    }
    if lower.ends_with("_runs")
        || lower.ends_with("-runs")
        || lower.ends_with(".egg-info")
        || lower.ends_with(".dist-info")
        || lower.starts_with("cmake-build-")
    {
        return true;
    }
    PROJECT_OUTPUT_COMPONENTS.contains(&lower.as_str()) && project_marker(parent)
}

fn vcs_prefix(path: &str) -> Option<String> {
    for marker in [
        "/.git/objects/",
        "/.git/refs/",
        "/.git/logs/",
        "/.git/lfs/",
        "/.jj/repo/",
        "/.jj/working_copy/",
        "/.jj/op_store/",
        "/.jj/op_heads/",
    ] {
        if let Some(index) = path.find(marker) {
            return Some(path[..index + marker.len() - 1].to_string());
        }
    }
    path.find("/.git/index")
        .map(|index| path[..index + "/.git/index".len()].to_string())
}

/// Component-only classification for rule suppression. Unlike `prefix`, this
/// does not check project markers or restrict the path to user-writable roots.
pub fn looks_generated(path: &str) -> bool {
    if vcs_prefix(path).is_some() {
        return true;
    }
    Path::new(path).components().any(|component| {
        component.as_os_str().to_str().is_some_and(|name| {
            let lower = name.to_ascii_lowercase();
            ALWAYS_OUTPUT_COMPONENTS.contains(&lower.as_str())
                || PROJECT_OUTPUT_COMPONENTS.contains(&lower.as_str())
                || lower.ends_with("_runs")
                || lower.ends_with("-runs")
                || lower.ends_with(".egg-info")
                || lower.ends_with(".dist-info")
                || lower.starts_with("cmake-build-")
        })
    })
}

/// Return the nearest generated-output directory prefix for a path, or `None`
/// for normal source/config/data paths. The caller can insert the prefix into
/// the kernel ignore map so later events are dropped before they reach the ring.
pub fn prefix(path: &str) -> Option<String> {
    if !Path::new(path).is_absolute()
        || !user_writable(Path::new(path))
        || sensitive(Path::new(path))
    {
        return None;
    }
    if let Some(prefix) = vcs_prefix(path) {
        return Some(prefix);
    }
    let path = Path::new(path);
    let mut parent = PathBuf::new();
    for component in path.components() {
        let name = component.as_os_str().to_str()?;
        // Never collapse /tmp or another top-level root into an auto-noise
        // prefix; those are handled by the configured noise paths.
        if parent != Path::new("/") && generated_component(name, &parent) {
            let prefix = parent.join(name);
            return Some(prefix.to_string_lossy().into_owned());
        }
        parent.push(component.as_os_str());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_project_output_and_run_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), b"[package]\n").unwrap();
        let target = dir.path().join("target/debug/example");
        assert_eq!(
            prefix(target.to_str().unwrap()).as_deref(),
            Some(dir.path().join("target").to_string_lossy().as_ref())
        );

        let runs = dir.path().join("dom6bot_runs/win-1/output.json");
        std::fs::create_dir_all(runs.parent().unwrap()).unwrap();
        assert_eq!(
            prefix(runs.to_str().unwrap()).as_deref(),
            Some(dir.path().join("dom6bot_runs").to_string_lossy().as_ref())
        );

        let modules = dir.path().join("node_modules/pkg/index.js");
        std::fs::create_dir_all(modules.parent().unwrap()).unwrap();
        assert_eq!(
            prefix(modules.to_str().unwrap()).as_deref(),
            Some(dir.path().join("node_modules").to_string_lossy().as_ref())
        );
    }

    #[test]
    fn filters_vcs_bookkeeping_but_not_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let object = dir.path().join("repo/.git/objects/ab/cdef");
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        assert_eq!(
            prefix(object.to_str().unwrap()).as_deref(),
            Some(
                dir.path()
                    .join("repo/.git/objects")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        let index = dir.path().join("repo/.git/index.lock");
        assert_eq!(
            prefix(index.to_str().unwrap()).as_deref(),
            Some(
                dir.path()
                    .join("repo/.git/index")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        let config = dir.path().join("repo/.git/config");
        assert_eq!(prefix(config.to_str().unwrap()), None);
        let jj_store = dir.path().join("repo/.jj/repo/store/operation");
        std::fs::create_dir_all(jj_store.parent().unwrap()).unwrap();
        assert_eq!(
            prefix(jj_store.to_str().unwrap()).as_deref(),
            Some(dir.path().join("repo/.jj/repo").to_string_lossy().as_ref())
        );
    }

    #[test]
    fn ignores_source_sensitive_and_unmarked_directories() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src/main.rs");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        assert_eq!(prefix(source.to_str().unwrap()), None);

        let ssh = dir.path().join(".ssh/target/key");
        std::fs::create_dir_all(ssh.parent().unwrap()).unwrap();
        assert_eq!(prefix(ssh.to_str().unwrap()), None);

        let build = dir.path().join("build/output.bin");
        std::fs::create_dir_all(build.parent().unwrap()).unwrap();
        assert_eq!(prefix(build.to_str().unwrap()), None);

        assert_eq!(prefix("/etc/target/output"), None);
    }
}
