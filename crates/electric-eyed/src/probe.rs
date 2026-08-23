use std::path::Path;

pub fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn btf_available() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

pub fn running_as_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}
