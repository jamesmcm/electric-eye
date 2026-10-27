//! Deterministic explanations retain their observations, not only prose.
use crate::{
    api::ActivityEntry,
    flows::Flow,
    process::{ProcessRecord, key},
};
use electric_eye_core::{FileKind, ObservedEvent};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub id: String,
    pub kind: String,
    pub text: String,
    pub confidence: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub application: Option<crate::grouping::Attribution>,
    pub root_process: Option<String>,
    pub files: BTreeSet<String>,
    pub files_truncated: bool,
    pub bytes: u64,
    pub evidence: Vec<Value>,
    pub evidence_truncated: bool,
    pub root_exit_code: Option<i32>,
    #[serde(skip)]
    evidence_limit: usize,
}
impl Summary {
    fn new(id: String, kind: &str, entry: &ActivityEntry, evidence_limit: usize) -> Self {
        Self {
            id,
            kind: kind.into(),
            text: String::new(),
            confidence: "observed".into(),
            first_ms: entry.ts_ms,
            last_ms: entry.ts_ms,
            application: entry.application.clone(),
            root_process: entry.process.as_ref().map(key),
            files: BTreeSet::new(),
            files_truncated: false,
            bytes: 0,
            evidence: Vec::new(),
            evidence_truncated: false,
            root_exit_code: None,
            evidence_limit,
        }
    }
    fn evidence(&mut self, value: Value) {
        if self.evidence.len() < self.evidence_limit {
            self.evidence.push(value);
        } else {
            self.evidence_truncated = true;
        }
    }
}
pub struct Engine {
    pub rows: crate::cache::Recent<Summary>,
    dirty: HashSet<String>,
    process_build: crate::cache::Recent<String>,
    writes: HashMap<(String, String), (u64, Value)>,
    received: crate::cache::Recent<(u64, String)>,
    flow_received: crate::cache::Recent<u64>,
    limits: crate::config::Limits,
    config: crate::config::CorrelationConfig,
    rules: crate::config::RuleConfig,
}
impl Default for Engine {
    fn default() -> Self {
        Self::configured(&crate::config::Config::default())
    }
}
impl Engine {
    pub fn configured(config: &crate::config::Config) -> Self {
        let limits = &config.limits;
        Self {
            rows: crate::cache::Recent::new(limits.summary_entries),
            dirty: HashSet::new(),
            limits: limits.clone(),
            config: config.correlation.clone(),
            rules: config.rules.clone(),
            process_build: crate::cache::Recent::new(limits.correlation_processes),
            writes: HashMap::new(),
            received: crate::cache::Recent::new(limits.application_entries),
            flow_received: crate::cache::Recent::new(limits.flow_entries),
        }
    }
    fn download_like_noise(&self, entry: &ActivityEntry, path: &str) -> bool {
        let name = entry
            .application
            .as_ref()
            .map(|app| app.name.as_str())
            .unwrap_or_default();
        let high_churn_non_browser = !crate::rules::is_browser_app(name, &self.rules)
            && crate::rules::is_high_churn_app(name, &self.rules);
        high_churn_non_browser || download_noise_path(path)
    }
}
fn download_noise_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "/.cache/",
        "/cache/",
        "/caches/",
        "/logs/",
        "/log/",
        "/.mozilla/",
        "/.config/chromium/",
        "/.config/google-chrome/",
        "/.hermes/",
        "/.codex/",
        "/.local/share/opencode/",
        "/target/",
        "/node_modules/",
        "/var/lib/tailscale/",
    ];
    const SUFFIXES: &[&str] = &[
        ".log",
        ".sqlite",
        ".sqlite-wal",
        ".sqlite-shm",
        ".db",
        ".db-wal",
        ".db-shm",
        "-wal",
        "-shm",
        ".kdl",
        ".lock",
        ".part",
    ];
    MARKERS.iter().any(|marker| path.contains(marker))
        || SUFFIXES.iter().any(|suffix| path.ends_with(suffix))
        || path.contains(".log.")
}
fn observation(e: &ActivityEntry) -> Value {
    json!({"event_id":e.event_id,"ts_ms":e.ts_ms,"process":e.process,"executable":e.exe,"observation":e.event,"syscall_result":e.syscall_result,"path_resolution":e.path_resolution})
}
fn compiler(p: &ProcessRecord, config: &crate::config::CorrelationConfig) -> bool {
    let name = p
        .executable
        .as_deref()
        .unwrap_or_default()
        .rsplit('/')
        .next()
        .unwrap_or_default();
    if config.cross_compiler_patterns
        && (name.ends_with("-gcc") || name.starts_with("gcc-") || name.ends_with("-g++"))
    {
        return true;
    }
    config.compiler_names.iter().any(|n| n == name)
        || config.build_driver_names.iter().any(|n| n == name)
            && p.argv
                .get(1)
                .is_some_and(|s| config.build_subcommands.contains(s))
}
impl Engine {
    pub fn flow(&mut self, f: &Flow) {
        let old = self.flow_received.get(&f.id).copied().unwrap_or(0);
        if f.closed_ms.is_some() {
            self.flow_received.remove(&f.id);
        } else {
            self.flow_received
                .insert(f.id.clone(), f.last_seen_ms, f.received);
        }
        if f.received > old
            && let Some(app) = &f.application
        {
            self.received.insert(
                app.task_id.clone(),
                f.last_seen_ms,
                (f.last_seen_ms, f.id.clone()),
            );
        }
    }
    pub fn observe(&mut self, e: &ActivityEntry, p: Option<&ProcessRecord>) {
        if e.syscall_result.is_some_and(|n| n < 0)
            || matches!(e.path_resolution.as_deref(), Some("lexical" | "unresolved"))
        {
            return;
        }
        let Some(identity) = &e.process else {
            return;
        };
        let proc = key(identity);
        let app = e.application.as_ref();
        let name = app.map(|a| a.name.as_str()).unwrap_or("Application");
        if matches!(e.event, ObservedEvent::Exec(_)) {
            self.process_build.remove(&proc);
        }
        if matches!(e.event, ObservedEvent::Exec(_) | ObservedEvent::Fork(_))
            && let Some(p) = p
        {
            let inherited = p
                .parent
                .as_ref()
                .and_then(|parent| self.process_build.get(&key(parent)))
                .cloned();
            if let Some(build) = inherited {
                self.process_build.insert(proc.clone(), e.ts_ms, build);
            } else if matches!(e.event, ObservedEvent::Exec(_))
                && self.config.build_session
                && compiler(p, &self.config)
            {
                let id = format!("build:{proc}:{}", p.exec_id);
                let mut s =
                    Summary::new(id.clone(), "build_session", e, self.limits.summary_evidence);
                s.text = format!(
                    "Build command observed in {}",
                    p.cwd.as_deref().unwrap_or("an unknown directory")
                );
                s.confidence = "correlated".into();
                s.evidence(observation(e));
                self.rows.insert(id.clone(), s.last_ms, s);
                self.process_build.insert(proc.clone(), e.ts_ms, id.clone());
                self.dirty.insert(id);
            }
            if matches!(e.event, ObservedEvent::Exec(_))
                && self.config.application_start
                && app.is_some_and(|a| a.root == *identity)
            {
                let id = format!("startup:{proc}:{}", p.exec_id);
                let mut s = Summary::new(
                    id.clone(),
                    "application_start",
                    e,
                    self.limits.summary_evidence,
                );
                s.text = format!(
                    "{name} started {}",
                    p.executable.as_deref().unwrap_or("an unknown executable")
                );
                s.evidence(observation(e));
                self.rows.insert(id.clone(), s.last_ms, s);
                self.dirty.insert(id);
            }
        }
        if let Some(id) = self.process_build.get(&proc).cloned()
            && let Some(s) = self.rows.get_mut(&id)
        {
            let mut changed = false;
            if let ObservedEvent::FileWrite(file) = &e.event
                && file.kind == FileKind::Write
            {
                if s.files.len() < self.limits.summary_files {
                    s.files.insert(file.path.clone());
                } else if !s.files.contains(&file.path) {
                    s.files_truncated = true;
                }
                s.bytes = s.bytes.saturating_add(file.bytes.unwrap_or(0));
                changed = true;
            }
            if matches!(e.event, ObservedEvent::Exit(_)) && s.root_process.as_deref() == Some(&proc)
            {
                s.root_exit_code = p.and_then(|p| p.exit_code);
                changed = true;
            }
            if changed {
                s.last_ms = s.last_ms.max(e.ts_ms);
                s.evidence(observation(e));
                s.text = format!(
                    "Build task modified {}{} observed files ({} application bytes){}",
                    if s.files_truncated { "at least " } else { "" },
                    s.files.len(),
                    s.bytes,
                    s.root_exit_code
                        .map(|code| format!("; root command exited with code {code}"))
                        .unwrap_or_default()
                );
                let last = s.last_ms;
                self.dirty.insert(id.clone());
                self.rows.touch(&id, last);
            }
        }
        if let ObservedEvent::FileWrite(file) = &e.event
            && file.kind == FileKind::Write
        {
            if self.writes.len() >= self.limits.correlation_writes {
                self.writes
                    .retain(|_, (ts, _)| e.ts_ms.saturating_sub(*ts) <= self.config.save_window_ms);
                if self.writes.len() >= self.limits.correlation_writes {
                    self.writes.clear();
                }
            }
            self.writes.insert(
                (
                    format!("{proc}:exec:{}", p.map(|p| p.exec_id).unwrap_or(0)),
                    file.path.clone(),
                ),
                (e.ts_ms, observation(e)),
            );
            if self.config.download_like
                && !self.download_like_noise(e, &file.path)
                && let Some(app) = app
                && let Some((ts, flow)) = self.received.get(&app.task_id)
                && e.ts_ms.saturating_sub(*ts) <= self.config.download_window_ms
            {
                let id = format!("network-write:{}:{}", app.task_id, file.path);
                let mut s = self.rows.get(&id).cloned().unwrap_or_else(|| {
                    Summary::new(id.clone(), "download_like", e, self.limits.summary_evidence)
                });
                s.text = format!(
                    "{name} received network data and wrote {}; content linkage is unverified",
                    file.path
                );
                s.confidence = "heuristic".into();
                s.last_ms = e.ts_ms;
                s.files.insert(file.path.clone());
                s.bytes = s.bytes.saturating_add(file.bytes.unwrap_or(0));
                s.evidence(json!({"flow_id":flow,"ts_ms":ts,"relationship":format!("same application task, within {}ms", self.config.download_window_ms)}));
                s.evidence(observation(e));
                self.rows.insert(id.clone(), s.last_ms, s);
                self.dirty.insert(id);
            }
        }
        if self.config.save_sequence
            && let ObservedEvent::FileRename(rename) = &e.event
            && let Some((ts, write)) = self.writes.remove(&(
                format!("{proc}:exec:{}", p.map(|p| p.exec_id).unwrap_or(0)),
                rename.from_path.clone(),
            ))
            && e.ts_ms.saturating_sub(ts) <= self.config.save_window_ms
        {
            let id = format!("save:{proc}:{}:{}", e.ts_ms, rename.to_path);
            let mut s = Summary::new(id.clone(), "save_sequence", e, self.limits.summary_evidence);
            s.text = format!(
                "{name} wrote {} then renamed it to {}",
                rename.from_path, rename.to_path
            );
            s.confidence = "correlated".into();
            s.files.insert(rename.from_path.clone());
            s.files.insert(rename.to_path.clone());
            s.evidence(write);
            s.evidence(observation(e));
            self.rows.insert(id.clone(), s.last_ms, s);
            self.dirty.insert(id);
        }
        if matches!(e.event, ObservedEvent::Exit(_)) {
            self.process_build.remove(&proc);
        }
    }
    pub fn needs_flush(&self) -> bool {
        self.dirty.len() >= self.limits.summary_flush_entries
    }
    pub fn drain(&mut self) -> Vec<Summary> {
        let pending: Vec<_> = self
            .dirty
            .drain()
            .filter_map(|id| self.rows.get(&id).cloned())
            .collect();
        for summary in &pending {
            self.rows
                .insert(summary.id.clone(), summary.last_ms, summary.clone());
        }
        let expired: Vec<_> = self
            .process_build
            .entries()
            .filter(|(_, id)| self.rows.get(id).is_none())
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.process_build.remove(&key);
        }
        pending
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use electric_eye_core::{FileEvent, RenameEvent};
    fn entry(event: ObservedEvent) -> ActivityEntry {
        ActivityEntry {
            ts_ms: 1000,
            syscall_result: Some(0),
            event_id: Some("test-event".into()),
            process: Some(crate::api::ProcessIdentity {
                pid: 1,
                start_ns: 1,
                boot_id: "boot".into(),
            }),
            process_info: None,
            application: None,
            path_resolution: Some("kernel".into()),
            event,
            unit: None,
            nix: None,
            parent: None,
            exe: Some("/usr/bin/test".into()),
        }
    }
    #[test]
    fn download_like_path_filter_rejects_logs_caches_and_databases() {
        for path in [
            "/var/lib/plex/Plex Media Server/Logs/Plex Media Server.log",
            "/var/lib/tailscale/tailscaled.log1.txt",
            "/home/alice/.cache/zellij/session-metadata.kdl",
            "/home/alice/.local/share/opencode/opencode.db-wal",
            "/home/alice/.hermes/kanban.db-shm",
            "/home/alice/.codex/sessions/2026/10/30/rollout.jsonl",
            "/home/alice/.mozilla/firefox/profile/cookies.sqlite-wal",
            "/home/alice/project/target/debug/output",
        ] {
            assert!(download_noise_path(path), "{path}");
        }
        assert!(!download_noise_path("/home/alice/Downloads/linux.iso"));
        assert!(!download_noise_path("/home/alice/Documents/report.pdf"));
    }

    fn attribution(name: &str, task: &str) -> crate::grouping::Attribution {
        crate::grouping::Attribution {
            id: format!("app:{name}"),
            name: name.into(),
            task_id: task.into(),
            root: crate::api::ProcessIdentity {
                pid: 1,
                start_ns: 1,
                boot_id: "boot".into(),
            },
            reason: "test".into(),
            confidence: "strong".into(),
            desktop_id: None,
        }
    }

    fn write_entry(path: &str, app: crate::grouping::Attribution, exe: &str) -> ActivityEntry {
        let mut e = entry(ObservedEvent::FileWrite(FileEvent {
            pid: 1,
            uid: 1000,
            comm: app.name.clone(),
            path: path.into(),
            kind: FileKind::Write,
            bytes: Some(1024),
            count: Some(1),
        }));
        e.application = Some(app);
        e.exe = Some(exe.into());
        e
    }

    #[test]
    fn download_like_skips_high_churn_apps_but_not_browser_downloads() {
        let mut c = Engine::default();
        let plex = attribution("Plex Media Server", "plex-task");
        c.received
            .insert(plex.task_id.clone(), 900, (900, "flow-plex".into()));
        c.observe(
            &write_entry("/home/alice/Downloads/plex-log.bin", plex, "/usr/bin/plex"),
            None,
        );
        assert!(
            c.drain()
                .iter()
                .all(|summary| summary.kind != "download_like"),
            "high-churn app produced a download-like summary"
        );

        let firefox = attribution("Firefox", "firefox-task");
        c.received
            .insert(firefox.task_id.clone(), 900, (900, "flow-firefox".into()));
        c.observe(
            &write_entry(
                "/home/alice/Downloads/linux.iso",
                firefox,
                "/usr/lib/firefox/firefox",
            ),
            None,
        );
        assert!(
            c.drain()
                .iter()
                .any(|summary| summary.kind == "download_like"),
            "browser download was suppressed"
        );
    }

    #[test]
    fn write_then_rename_keeps_both_observations() {
        let mut c = Engine::default();
        c.observe(
            &entry(ObservedEvent::FileWrite(FileEvent {
                pid: 1,
                uid: 1000,
                comm: "test".into(),
                path: "/work/.temporary".into(),
                kind: FileKind::Write,
                bytes: Some(4),
                count: Some(1),
            })),
            None,
        );
        c.observe(
            &entry(ObservedEvent::FileRename(RenameEvent {
                pid: 1,
                uid: 1000,
                comm: "test".into(),
                from_path: "/work/.temporary".into(),
                to_path: "/work/config".into(),
            })),
            None,
        );
        let s = c.drain();
        assert_eq!(s[0].kind, "save_sequence");
        assert_eq!(s[0].evidence.len(), 2);
        assert!(!s[0].text.contains("succeeded"));
    }
}
