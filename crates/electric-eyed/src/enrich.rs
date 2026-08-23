use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStat {
    pub ppid: u32,
    pub start_ticks: u64,
}

pub fn resolve_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

pub fn process_stat(pid: u32) -> Option<ProcessStat> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&raw)
}

pub fn parse_stat(raw: &str) -> Option<ProcessStat> {
    let after_comm = raw.rsplit_once(") ")?;
    let fields = after_comm.1.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 {
        return None;
    }
    Some(ProcessStat {
        ppid: fields[1].parse().ok()?,
        start_ticks: fields[19].parse().ok()?,
    })
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

    #[test]
    fn parses_stat_with_parens_in_comm() {
        let raw = "123 (chrome:renderer) S 456 123 123 0 -1 4194560 ".to_owned()
            + &"0 ".repeat(12)
            + "987654 0 0 0 0 0 0";
        let stat = parse_stat(&raw).expect("well-formed stat line must parse");
        assert_eq!(stat.ppid, 456);
        assert_eq!(stat.start_ticks, 987654);
    }

    #[test]
    fn rejects_malformed_stat() {
        assert!(parse_stat("garbage").is_none());
        assert!(parse_stat("").is_none());
        let short = "12 (sh) S 1".to_string();
        assert!(parse_stat(&short).is_none());
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
