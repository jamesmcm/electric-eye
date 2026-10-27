use crate::{api::ProcessIdentity, collector::cstr, config::Config, wire};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn key(p: &ProcessIdentity) -> String {
    format!("{}:{}:{}", p.boot_id, p.pid, p.start_ns)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub id: String,
    pub identity: ProcessIdentity,
    pub parent: Option<ProcessIdentity>,
    pub comm: String,
    pub executable: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub argv: Vec<String>,
    pub argv_truncated: bool,
    pub argv_captured: bool,
    pub cwd: Option<String>,
    pub cgroup: Option<String>,
    pub system_unit: Option<String>,
    pub user_unit: Option<String>,
    pub exec_id: u32,
    pub source: String,
    pub identity_exact: bool,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub exited_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub superseded_by: Option<String>,
    pub package: Option<crate::provenance::Provenance>,
    pub application: Option<crate::grouping::Attribution>,
}
pub struct Registry {
    records: HashMap<String, ProcessRecord>,
    retired: crate::cache::Recent<ProcessRecord>,
    inventory_ids: HashMap<u32, ProcessIdentity>,
    pending_superseded: Vec<ProcessIdentity>,
}
impl Default for Registry {
    fn default() -> Self {
        Self::with_limits(&crate::config::Limits::default())
    }
}
impl Registry {
    pub fn with_limits(limits: &crate::config::Limits) -> Self {
        Self {
            records: HashMap::new(),
            retired: crate::cache::Recent::new(limits.retired_process_entries),
            inventory_ids: HashMap::new(),
            pending_superseded: Vec::new(),
        }
    }
}
impl Registry {
    pub fn set_application(&mut self, id: &ProcessIdentity, app: crate::grouping::Attribution) {
        if let Some(p) = self
            .records
            .get_mut(&key(id))
            .or_else(|| self.retired.get_mut(&key(id)))
        {
            p.application = Some(app);
        }
    }
    pub fn set_package(
        &mut self,
        id: &ProcessIdentity,
        package: Option<crate::provenance::Provenance>,
    ) {
        if let Some(p) = self
            .records
            .get_mut(&key(id))
            .or_else(|| self.retired.get_mut(&key(id)))
        {
            p.package = package;
        }
    }
    pub fn get(&self, id: &ProcessIdentity) -> Option<&ProcessRecord> {
        self.records
            .get(&key(id))
            .or_else(|| self.retired.get(&key(id)))
    }
    pub fn observe(
        &mut self,
        r: &wire::Record,
        boot: &str,
        ts: u64,
        config: &Config,
    ) -> ProcessRecord {
        let identity = ProcessIdentity {
            boot_id: boot.into(),
            pid: r.pid,
            start_ns: r.start_ns,
        };
        let mut p = self
            .get(&identity)
            .cloned()
            .or_else(|| {
                // EXEC always starts a fresh metadata generation. Other events can
                // retain a matching startup snapshot while acquiring an exact ID.
                let old = self
                    .inventory_ids
                    .get(&identity.pid)
                    .and_then(|id| self.get(id))?;
                (r.kind != wire::EXEC
                    && old.identity.boot_id == identity.boot_id
                    && old.identity.start_ns / tick_ns() == identity.start_ns / tick_ns()
                    && old.executable.as_deref() == Some(cstr(&r.exe).as_str()))
                .then(|| {
                    let mut p = old.clone();
                    p.id = key(&identity);
                    p.identity = identity.clone();
                    p.application = None;
                    p
                })
            })
            .unwrap_or_else(|| ProcessRecord::empty(identity.clone(), ts));
        p.identity_exact = true;
        p.source = "kernel".into();
        p.last_seen_ms = ts;
        p.exec_id = r.exec_id;
        p.comm = cstr(&r.comm);
        p.uid = r.uid;
        p.euid = r.euid;
        let exe = cstr(&r.exe);
        if r.kind == wire::EXEC && exe.is_empty() {
            p.executable = None;
        }
        if !exe.is_empty() {
            p.executable = Some(exe);
        }
        if r.ppid != 0 && r.parent_start_ns != 0 {
            p.parent = Some(ProcessIdentity {
                boot_id: boot.into(),
                pid: r.ppid,
                start_ns: r.parent_start_ns,
            });
        }
        if matches!(r.kind, wire::EXEC | wire::FORK | wire::EXIT) {
            if r.metadata_flags & 1 != 0 {
                p.cwd = Some(cstr(&r.path));
            }
            if r.metadata_flags & 2 != 0 {
                let n = if r.count > 0 {
                    (r.count as usize).min(512)
                } else {
                    r.path2
                        .iter()
                        .rposition(|b| *b != 0)
                        .map_or(0, |i| (i + 2).min(512))
                };
                let (argv, truncated) = config.argv(&r.path2[..n]);
                p.argv = argv;
                p.argv_truncated = truncated || r.metadata_flags & 8 != 0;
                p.argv_captured = config.capture_argv;
            } else if r.kind == wire::EXEC {
                p.argv.clear();
                p.argv_captured = false;
            }
            if r.metadata_flags & 4 != 0 {
                p.cgroup = Some(cstr(&r.cgroup));
            }
            if r.kind == wire::EXIT {
                p.exited_ms = Some(ts);
                let sig = r.exit_code & 127;
                if sig == 0 {
                    p.exit_code = Some((r.exit_code >> 8) & 255);
                } else {
                    p.signal = Some(sig);
                }
            }
        }
        if p.cgroup.is_none() {
            p.cgroup = live_cgroup(&identity);
        }
        let (system, user) = units(p.cgroup.as_deref().unwrap_or_default());
        p.system_unit = system;
        p.user_unit = user;
        // Inventory identities are explicitly approximate. Link, rather than
        // silently rewrite, a matching observed kernel identity.
        let tick = tick_ns();
        if let Some(old_id) = self.inventory_ids.remove(&identity.pid)
            && let Some(old) = self.records.get_mut(&key(&old_id))
            && old.identity.boot_id == boot
            && old.identity.start_ns / tick == identity.start_ns / tick
            && old.id != p.id
        {
            old.superseded_by = Some(p.id.clone());
            self.pending_superseded.push(old.identity.clone());
            self.retired
                .insert(old.id.clone(), old.last_seen_ms, old.clone());
            self.records.remove(&key(&old_id));
        }
        if r.kind == wire::EXIT {
            self.records.remove(&p.id);
            self.retired.insert(p.id.clone(), ts, p.clone());
        } else {
            self.records.insert(p.id.clone(), p.clone());
        }
        p
    }
    pub fn inventory(&mut self, boot: &str, config: &Config) -> Vec<ProcessRecord> {
        let mut rows = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>()
                    && let Some(p) = snapshot(pid, boot, config)
                {
                    rows.push(p);
                }
            }
        }
        let identities: HashMap<_, _> = rows
            .iter()
            .map(|p| (p.identity.pid, p.identity.clone()))
            .collect();
        for p in &mut rows {
            let ppid = crate::enrich::process_stat(p.identity.pid)
                .map(|s| s.ppid)
                .unwrap_or(0);
            p.parent = identities.get(&ppid).cloned();
            self.inventory_ids
                .insert(p.identity.pid, p.identity.clone());
            self.records.insert(p.id.clone(), p.clone());
        }
        rows
    }
    pub fn drain_superseded(&mut self) -> Vec<ProcessRecord> {
        self.pending_superseded
            .drain(..)
            .filter_map(|id| self.retired.get(&key(&id)).cloned())
            .collect()
    }
}
impl ProcessRecord {
    #[cfg(test)]
    pub(crate) fn synthetic(identity: ProcessIdentity, ts: u64, comm: &str, argv: &[&str]) -> Self {
        let mut record = Self::empty(identity, ts);
        record.comm = comm.into();
        record.executable = Some(format!("/usr/bin/{comm}"));
        record.argv = argv.iter().map(|arg| (*arg).to_string()).collect();
        record.argv_captured = true;
        record
    }
    fn empty(identity: ProcessIdentity, ts: u64) -> Self {
        Self {
            id: key(&identity),
            identity,
            parent: None,
            comm: String::new(),
            executable: None,
            uid: 0,
            euid: 0,
            argv: Vec::new(),
            argv_truncated: false,
            argv_captured: false,
            cwd: None,
            cgroup: None,
            system_unit: None,
            user_unit: None,
            exec_id: 0,
            source: "kernel".into(),
            identity_exact: true,
            first_seen_ms: ts,
            last_seen_ms: ts,
            exited_ms: None,
            exit_code: None,
            signal: None,
            superseded_by: None,
            package: None,
            application: None,
        }
    }
}
fn tick_ns() -> u64 {
    1_000_000_000 / (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64)
}
fn live_cgroup(id: &ProcessIdentity) -> Option<String> {
    let before = crate::enrich::process_stat(id.pid)?;
    if before.start_ticks != id.start_ns / tick_ns() {
        return None;
    }
    let data = std::fs::read_to_string(format!("/proc/{}/cgroup", id.pid)).ok()?;
    if crate::enrich::process_stat(id.pid)?.start_ticks != before.start_ticks {
        return None;
    }
    data.lines()
        .find_map(|s| s.split_once("::").map(|(_, path)| path.to_string()))
}
pub fn units(path: &str) -> (Option<String>, Option<String>) {
    let mut system = None;
    let mut user = None;
    let mut in_user = false;
    for part in path.split('/') {
        if part.starts_with("user@") && part.ends_with(".service") {
            in_user = true;
            system = Some(part.into());
            continue;
        }
        if part.ends_with(".service") || part.ends_with(".scope") {
            if in_user {
                user = Some(part.into());
            } else {
                system = Some(part.into());
            }
        }
    }
    (system, user)
}
fn snapshot(pid: u32, boot: &str, config: &Config) -> Option<ProcessRecord> {
    use std::io::Read;
    let stat = crate::enrich::process_stat(pid)?;
    let id = ProcessIdentity {
        boot_id: boot.into(),
        pid,
        start_ns: stat.start_ticks * tick_ns(),
    };
    let mut p = ProcessRecord::empty(id, crate::api::now_ms());
    p.source = "inventory".into();
    p.identity_exact = false;
    p.comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()?
        .trim()
        .into();
    p.executable = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|s| s.display().to_string());
    p.cwd = std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|s| s.display().to_string());
    if config.capture_argv {
        let mut data = Vec::new();
        if std::fs::File::open(format!("/proc/{pid}/cmdline"))
            .and_then(|f| f.take(513).read_to_end(&mut data))
            .is_ok()
        {
            let (a, t) = config.argv(&data);
            p.argv = a;
            p.argv_truncated = t || data.len() > 512;
            p.argv_captured = true;
        }
    }
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status"))
        && let Some(line) = status.lines().find(|s| s.starts_with("Uid:"))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        p.uid = fields.get(1)?.parse().ok()?;
        p.euid = fields.get(2)?.parse().ok()?;
    }
    p.cgroup = live_cgroup(&p.identity);
    let (system, user) = units(p.cgroup.as_deref().unwrap_or_default());
    p.system_unit = system;
    p.user_unit = user;
    (crate::enrich::process_stat(pid)?.start_ticks == stat.start_ticks).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_identity_metadata_and_exit_survive_without_proc() {
        let mut registry = Registry::default();
        let mut r = wire::Record::ZERO;
        r.pid = 4_000_000_000;
        r.start_ns = 123;
        r.ppid = 4_000_000_001;
        r.parent_start_ns = 99;
        r.uid = 1000;
        r.euid = 1001;
        r.exec_id = 3;
        r.kind = wire::EXEC;
        r.exe[..9].copy_from_slice(b"/bin/test");
        r.path[..5].copy_from_slice(b"/work");
        r.path2[..26].copy_from_slice(b"test\0--token\0secret-value\0");
        r.metadata_flags = 3;
        let p = registry.observe(&r, "boot", 1000, &Config::default());
        assert_eq!(p.argv, vec!["test", "--token", "[redacted]"]);
        assert_eq!(p.parent.unwrap().start_ns, 99);
        assert_eq!(p.cwd.as_deref(), Some("/work"));
        assert_eq!(p.euid, 1001);
        r.kind = wire::EXIT;
        r.metadata_flags = 0;
        r.exit_code = 7 << 8;
        let p = registry.observe(&r, "boot", 2000, &Config::default());
        assert_eq!(p.exit_code, Some(7));
        assert_eq!(p.argv[2], "[redacted]");
        assert_eq!(p.exited_ms, Some(2000));
    }
    #[test]
    fn exited_process_churn_does_not_evict_a_live_actors_metadata() {
        let mut registry = Registry {
            retired: crate::cache::Recent::new(1),
            ..Registry::default()
        };
        let mut r = wire::Record::ZERO;
        r.pid = 4000000000;
        r.start_ns = 1;
        r.kind = wire::EXEC;
        r.metadata_flags = 2;
        r.path2[..5].copy_from_slice(b"tool\0");
        r.count = 5;
        registry.observe(&r, "boot", 1, &Config::default());
        let live = ProcessIdentity {
            pid: r.pid,
            start_ns: r.start_ns,
            boot_id: "boot".into(),
        };
        for pid in 4000000001..4000000010 {
            r.pid = pid;
            r.start_ns = pid as u64;
            r.kind = wire::EXIT;
            registry.observe(&r, "boot", 2, &Config::default());
        }
        assert_eq!(registry.get(&live).unwrap().argv, vec!["tool"]);
        assert_eq!(registry.records.len(), 1);
        assert_eq!(registry.retired.len(), 1);
    }
    #[test]
    fn inventory_supersession_is_reported_once_without_refreshing_retention() {
        let mut registry = Registry::default();
        let id = ProcessIdentity {
            boot_id: "boot".into(),
            pid: 4_000_000_000,
            start_ns: tick_ns(),
        };
        let mut old = ProcessRecord::empty(id.clone(), 100);
        old.identity_exact = false;
        old.source = "inventory".into();
        registry.inventory_ids.insert(id.pid, id.clone());
        registry.records.insert(old.id.clone(), old);
        let mut r = wire::Record::ZERO;
        r.pid = 4_000_000_000;
        r.start_ns = tick_ns() + 1;
        registry.observe(&r, "boot", 200, &Config::default());
        let updated = registry.drain_superseded();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].last_seen_ms, 100);
        assert!(updated[0].superseded_by.is_some());
        registry.observe(&r, "boot", 300, &Config::default());
        assert!(registry.drain_superseded().is_empty());
    }
    #[test]
    fn resolves_user_and_system_units_from_nested_cgroups() {
        assert_eq!(
            units(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope/worker"
            ),
            (
                Some("user@1000.service".into()),
                Some("app-firefox.scope".into())
            )
        );
    }
}

#[cfg(test)]
mod review_cases {
    use super::*;
    #[test]
    fn review_inventory_metadata_survives_an_exact_file_observation() {
        let mut registry = Registry::default();
        let id = ProcessIdentity {
            boot_id: "boot".into(),
            pid: 4_000_000_000,
            start_ns: tick_ns(),
        };
        let mut old = ProcessRecord::empty(id.clone(), 100);
        old.identity_exact = false;
        old.source = "inventory".into();
        old.executable = Some("/usr/bin/python3".into());
        old.argv = vec!["python3".into(), "/work/server.py".into()];
        old.argv_captured = true;
        old.cwd = Some("/work".into());
        registry.inventory_ids.insert(id.pid, id.clone());
        registry.records.insert(old.id.clone(), old);
        let mut raw = wire::Record::ZERO;
        raw.pid = id.pid;
        raw.start_ns = tick_ns() + 1;
        raw.kind = wire::WRITE;
        raw.exe[..16].copy_from_slice(b"/usr/bin/python3");
        let exact = registry.observe(&raw, "boot", 200, &Config::default());
        assert_eq!(exact.argv, vec!["python3", "/work/server.py"]);
        assert_eq!(exact.cwd.as_deref(), Some("/work"));
    }
}
