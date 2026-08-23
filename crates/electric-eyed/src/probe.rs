use std::collections::HashSet;
use std::path::Path;

pub const MIN_KERNEL: (u64, u64) = (5, 8);

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn kernel_release_tuple() -> Option<(u64, u64)> {
    let release = kernel_release();
    let mut parts = release.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().unwrap_or(0);
    Some((major, minor))
}

pub fn ringbuf_supported() -> bool {
    match kernel_release_tuple() {
        Some((major, minor)) => (major, minor) >= MIN_KERNEL,
        None => false,
    }
}

pub fn btf_available() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

pub fn running_as_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

pub fn available_ksyms() -> std::io::Result<HashSet<String>> {
    let text = std::fs::read_to_string("/proc/kallsyms")?;
    let mut names = HashSet::new();
    for line in text.lines() {
        let mut columns = line.split_whitespace();
        let _addr = columns.next();
        let _type = columns.next();
        if let Some(name) = columns.next() {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}
