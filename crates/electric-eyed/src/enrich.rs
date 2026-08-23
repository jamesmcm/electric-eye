use std::path::PathBuf;

pub fn resolve_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

pub fn argv0(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let first = raw.split(|b| *b == 0).next()?;
    if first.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(first).into_owned())
    }
}

pub fn systemd_unit(pid: u32) -> Option<String> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let line = cgroup.lines().find_map(|line| {
        let (_, path) = line.split_once("::")?;
        Some(path)
    })?;
    let unit = line.rsplit('/').next()?.to_string();
    if (unit.ends_with(".scope") || unit.ends_with(".service")) && !unit.is_empty() {
        Some(unit)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_own_executable() {
        let exe = resolve_exe(std::process::id()).expect("test binary must have /proc/self/exe");
        assert!(exe.exists());
    }

    #[test]
    fn reads_own_argv0() {
        let argv = argv0(std::process::id());
        assert!(argv.is_some());
    }

    #[test]
    fn missing_process_yields_none() {
        let bogus = find_absent_pid();
        assert!(resolve_exe(bogus).is_none());
        assert!(argv0(bogus).is_none());
        assert!(systemd_unit(bogus).is_none());
    }

    fn find_absent_pid() -> u32 {
        for candidate in (u16::MAX as u32..u16::MAX as u32 + 4096).rev() {
            if !std::path::Path::new(&format!("/proc/{candidate}")).exists() {
                return candidate;
            }
        }
        panic!("no free pid found for the test");
    }
}
