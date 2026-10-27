use std::path::Path;

pub const MIN_KERNEL: (u64, u64) = (5, 17);

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

const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))?
        .split_whitespace()
        .nth(1)?;
    u64::from_str_radix(line, 16).ok()
}

pub fn can_load_bpf() -> bool {
    if running_as_root() {
        return true;
    }
    let Some(caps) = effective_capabilities() else {
        return false;
    };
    let required = (1_u64 << CAP_BPF) | (1_u64 << CAP_PERFMON);
    caps & required == required
}

pub fn parse_cpu_list(text: &str) -> Vec<u32> {
    let mut cpus = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let (Ok(start), Ok(end)) = (start.parse::<u32>(), end.parse::<u32>()) else {
                continue;
            };
            cpus.extend(start..=end);
        } else if let Ok(cpu) = part.parse::<u32>() {
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// CPUs that are currently online. Perf tracepoint/kprobe attachments are
/// per-CPU, so missing one silently loses events from that CPU.
pub fn online_cpus() -> std::io::Result<Vec<u32>> {
    match std::fs::read_to_string("/sys/devices/system/cpu/online") {
        Ok(text) => {
            let cpus = parse_cpu_list(&text);
            if cpus.is_empty() {
                Err(std::io::Error::other("online CPU list was empty"))
            } else {
                Ok(cpus)
            }
        }
        Err(err) => {
            let count = std::thread::available_parallelism()
                .map(|n| n.get())
                .map_err(|_| err)?;
            Ok((0..count as u32).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_ranges_and_singletons() {
        assert_eq!(parse_cpu_list("0-3,5,7-9\n"), vec![0, 1, 2, 3, 5, 7, 8, 9]);
        assert_eq!(parse_cpu_list("4"), vec![4]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }

    #[test]
    fn ignores_malformed_cpu_entries() {
        assert_eq!(parse_cpu_list("0-2,x,5-4,7"), vec![0, 1, 2, 7]);
    }

    #[test]
    fn online_cpu_list_is_never_empty_on_linux() {
        assert!(!online_cpus().expect("linux exposes online CPUs").is_empty());
    }
}
