use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use electric_eye_core::{FileKind, NetEvent, ObservedEvent};
use serde::Serialize;
use serde_json::{Value, json};

use crate::api::ActivityEntry;

const SENSITIVE_WINDOW_MS: u64 = 60_000;
const BULK_WINDOW_MS: u64 = 10_000;
const DEDUP_WINDOW_MS: u64 = 5 * 60_000;
const BULK_FILE_THRESHOLD: usize = 50;
const CREDENTIAL_CATEGORY_THRESHOLD: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    pub fn priority(self) -> &'static str {
        match self {
            Severity::Medium => "4",
            Severity::High => "3",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaselineData {
    paths: HashSet<(String, String)>,
    network: HashSet<(String, String)>,
    network_counts: HashMap<String, usize>,
}

impl BaselineData {
    pub fn from_pairs(
        paths: impl IntoIterator<Item = (String, String)>,
        network: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        let paths: HashSet<(String, String)> = paths.into_iter().collect();
        let network: HashSet<(String, String)> = network.into_iter().collect();
        let mut network_counts = HashMap::new();
        for (comm, _) in &network {
            *network_counts.entry(comm.clone()).or_insert(0) += 1;
        }
        Self {
            paths,
            network,
            network_counts,
        }
    }

    pub fn knows_path(&self, comm: &str, path: &str) -> bool {
        self.paths.contains(&(comm.to_string(), path.to_string()))
    }

    pub fn knows_network(&self, comm: &str, destination: &str) -> bool {
        self.network
            .contains(&(comm.to_string(), destination.to_string()))
    }

    pub fn network_destination_count(&self, comm: &str) -> usize {
        self.network_counts.get(comm).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<(String, String)>,
}

impl Allowlist {
    pub fn load_default() -> Self {
        let mut allowlist = Self::default();
        for comm in [
            "unix_chkpwd",
            "sudo",
            "su",
            "login",
            "sshd",
            "systemd-userdbd",
        ] {
            for path in ["/etc/shadow", "/etc/passwd", "/etc/gshadow"] {
                allowlist.add(comm, path);
            }
        }
        for comm in ["sudo", "visudo"] {
            for path in ["/etc/sudoers", "/etc/sudoers.d"] {
                allowlist.add(comm, path);
            }
        }

        let path = std::env::var_os("ELECTRIC_EYE_ALLOWLIST")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/electric-eye/allowlist.conf"));
        if let Ok(text) = std::fs::read_to_string(path) {
            allowlist.parse(&text);
        }
        allowlist
    }

    pub fn parse(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(comm) = fields.next() else {
                continue;
            };
            let prefix: Vec<&str> = fields.collect();
            if prefix.is_empty() {
                continue;
            }
            self.add(comm, &prefix.join(" "));
        }
    }

    pub fn add(&mut self, comm: &str, prefix: &str) {
        self.rules.push((comm.to_string(), prefix.to_string()));
    }

    pub fn allows(&self, comm: &str, subject: &str) -> bool {
        self.rules.iter().any(|(allowed_comm, prefix)| {
            allowed_comm == comm && (prefix == "*" || subject.starts_with(prefix))
        })
    }

    pub fn allows_identity(&self, comm: &str, app: &str, subject: &str) -> bool {
        self.rules.iter().any(|(allowed, prefix)| {
            (allowed == comm || allowed == app) && (prefix == "*" || subject.starts_with(prefix))
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub ts_ms: u64,
    pub severity: Severity,
    pub title: String,
    pub pid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    pub details: Value,
}

#[derive(Default)]
pub struct AnomalyEngine {
    homes: HashMap<u32, Option<PathBuf>>,
    sensitive: HashMap<String, VecDeque<(u64, &'static str)>>,
    mutations: HashMap<String, VecDeque<(u64, String)>>,
    dedup: HashMap<String, u64>,
    baseline: BaselineData,
    allowlist: Allowlist,
}

impl AnomalyEngine {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_context(baseline: BaselineData, allowlist: Allowlist) -> Self {
        Self {
            baseline,
            allowlist,
            ..Self::default()
        }
    }

    pub fn observe(&mut self, entry: &ActivityEntry) -> Vec<Incident> {
        let mut incidents = Vec::new();
        self.observe_paths(entry, &mut incidents);
        self.observe_exec(entry, &mut incidents);
        self.observe_network(entry, &mut incidents);
        incidents
    }

    fn observe_paths(&mut self, entry: &ActivityEntry, incidents: &mut Vec<Incident>) {
        let (paths, operation): (Vec<&str>, &str) = match &entry.event {
            ObservedEvent::FileRead(event) => (vec![event.path.as_str()], "read"),
            ObservedEvent::FileOpen(event) => (
                vec![event.path.as_str()],
                match event.kind {
                    FileKind::Read => "read",
                    FileKind::Open => "open",
                    FileKind::Create => "create",
                    FileKind::Truncate => "truncate",
                    FileKind::Write => "write",
                    FileKind::Mmap => "mmap",
                    FileKind::Unlink => "unlink",
                },
            ),
            ObservedEvent::FileWrite(event) => (
                vec![event.path.as_str()],
                if event.kind == FileKind::Mmap {
                    "mmap"
                } else {
                    "write"
                },
            ),
            ObservedEvent::FileUnlink(event) => (vec![event.path.as_str()], "unlink"),
            ObservedEvent::FileRename(event) => (
                vec![event.from_path.as_str(), event.to_path.as_str()],
                "rename",
            ),
            _ => return,
        };

        let (pid, uid, comm) = event_identity(&entry.event);
        let app = app_key(entry);
        let home = self.home_for(uid);
        let now = entry.ts_ms;
        let mut categories = Vec::new();
        let mutation = matches!(
            &entry.event,
            ObservedEvent::FileUnlink(_) | ObservedEvent::FileRename(_)
        );

        for path in &paths {
            if self.allowlist.allows_identity(&comm, &app, path) {
                continue;
            }
            let known = self.baseline.knows_path(&app, path);
            if mutation && !known && !is_bulk_noise_path(path) {
                self.mutations
                    .entry(app.clone())
                    .or_default()
                    .push_back((now, (*path).to_string()));
            }
            if known {
                continue;
            }
            if let Some((category, severity)) = classify_with_home(path, home.as_deref()) {
                if category == "Browser credentials" && is_browser_app(&app) {
                    continue;
                }
                categories.push(category);
                let title = format!("Sensitive path access: {category}");
                if self.should_emit(&title, &app, Some(path), now) {
                    incidents.push(Incident {
                        ts_ms: now,
                        severity,
                        title,
                        pid,
                        comm: comm.clone(),
                        path: Some((*path).to_string()),
                        unit: entry.unit.clone(),
                        details: json!({
                            "rule": "sensitive_path",
                            "category": category,
                            "operation": operation,
                            "unit": entry.unit,
                            "nix": entry.nix,
                            "parent": entry.parent,
                        }),
                    });
                }
            } else if path.starts_with("/nix/store/")
                && !matches!(comm.as_str(), "nix-daemon" | "nix" | "nix-store")
            {
                let title = "Write attempted under /nix/store".to_string();
                if self.should_emit(&title, &app, Some(path), now) {
                    incidents.push(Incident {
                        ts_ms: now,
                        severity: Severity::High,
                        title,
                        pid,
                        comm: comm.clone(),
                        path: Some((*path).to_string()),
                        unit: entry.unit.clone(),
                        details: json!({
                            "rule": "nix_store_write",
                            "operation": operation,
                            "unit": entry.unit,
                            "nix": entry.nix,
                        }),
                    });
                }
            }
        }

        if !categories.is_empty() {
            let window = self.sensitive.entry(app.clone()).or_default();
            for category in categories {
                window.push_back((now, category));
            }
            while window
                .front()
                .is_some_and(|(ts, _)| now.saturating_sub(*ts) > SENSITIVE_WINDOW_MS)
            {
                window.pop_front();
            }
            let distinct: HashSet<&str> = window.iter().map(|(_, category)| *category).collect();
            if distinct.len() >= CREDENTIAL_CATEGORY_THRESHOLD {
                let title = "Credential sweep across multiple sensitive categories".to_string();
                if self.should_emit(&title, &app, None, now) {
                    incidents.push(Incident {
                        ts_ms: now,
                        severity: Severity::High,
                        title,
                        pid,
                        comm: comm.clone(),
                        path: None,
                        unit: entry.unit.clone(),
                        details: json!({
                            "rule": "credential_sweep",
                            "categories": distinct,
                            "unit": entry.unit,
                        }),
                    });
                }
            }
        }

        self.observe_bulk(pid, &app, &comm, entry.unit.as_deref(), now, incidents);
    }

    fn observe_bulk(
        &mut self,
        pid: u32,
        app: &str,
        comm: &str,
        unit: Option<&str>,
        now: u64,
        incidents: &mut Vec<Incident>,
    ) {
        if is_high_churn_app(app) {
            return;
        }
        let unique_count = {
            let Some(window) = self.mutations.get_mut(app) else {
                return;
            };
            while window
                .front()
                .is_some_and(|(ts, _)| now.saturating_sub(*ts) > BULK_WINDOW_MS)
            {
                window.pop_front();
            }
            let unique: HashSet<&str> = window.iter().map(|(_, path)| path.as_str()).collect();
            unique.len()
        };
        if unique_count >= BULK_FILE_THRESHOLD {
            let title = "Bulk filesystem mutation".to_string();
            if self.should_emit(&title, app, None, now) {
                incidents.push(Incident {
                    ts_ms: now,
                    severity: Severity::Medium,
                    title,
                    pid,
                    comm: comm.to_string(),
                    path: None,
                    unit: unit.map(str::to_string),
                    details: json!({
                        "rule": "bulk_mutation",
                        "files_in_window": unique_count,
                        "window_seconds": BULK_WINDOW_MS / 1000,
                    }),
                });
            }
        }
    }

    fn observe_exec(&mut self, entry: &ActivityEntry, incidents: &mut Vec<Incident>) {
        let ObservedEvent::Exec(event) = &entry.event else {
            return;
        };
        let exe = event.exe.display().to_string();
        if self.allowlist.allows(&event.comm, &exe) {
            return;
        }
        let Some(reason) = suspicious_execution(&exe, self.home_for(event.uid).as_deref()) else {
            return;
        };
        let title = "Executable launched from a suspicious location".to_string();
        if self.should_emit(&title, &event.comm, Some(&exe), entry.ts_ms) {
            incidents.push(Incident {
                ts_ms: entry.ts_ms,
                severity: Severity::Medium,
                title,
                pid: event.pid,
                comm: event.comm.clone(),
                path: Some(exe),
                unit: entry.unit.clone(),
                details: json!({
                    "rule": "suspicious_execution",
                    "reason": reason,
                    "parent": entry.parent,
                    "unit": entry.unit,
                    "nix": entry.nix,
                }),
            });
        }
    }

    fn observe_network(&mut self, entry: &ActivityEntry, incidents: &mut Vec<Incident>) {
        let net = match &entry.event {
            ObservedEvent::Connect(event) => event,
            ObservedEvent::Accept(event) => event,
            _ => return,
        };
        let app = app_key(entry);
        let destination = net.remote_endpoint();
        if self
            .allowlist
            .allows_identity(&net.comm, &app, &destination)
            || !is_public_destination(net)
        {
            return;
        }
        let is_connect = matches!(&entry.event, ObservedEvent::Connect(_));
        if !is_connect {
            return;
        }

        let recent = {
            let Some(window) = self.sensitive.get(&app) else {
                self.maybe_novel_network(entry, net, &app, &destination, incidents);
                return;
            };
            window
                .iter()
                .rev()
                .find(|(ts, _)| entry.ts_ms.saturating_sub(*ts) <= SENSITIVE_WINDOW_MS)
                .map(|(ts, category)| (*ts, *category))
        };
        if let Some((ts, category)) = recent {
            let title = "Sensitive path access followed by network egress".to_string();
            if self.should_emit(&title, &app, None, entry.ts_ms) {
                incidents.push(Incident {
                    ts_ms: entry.ts_ms,
                    severity: Severity::High,
                    title,
                    pid: net.pid,
                    comm: net.comm.clone(),
                    path: None,
                    unit: entry.unit.clone(),
                    details: json!({
                        "rule": "sensitive_egress",
                        "category": category,
                        "sensitive_ts_ms": ts,
                        "destination": destination,
                        "unit": entry.unit,
                    }),
                });
            }
            return;
        }

        self.maybe_novel_network(entry, net, &app, &destination, incidents);
    }

    fn maybe_novel_network(
        &mut self,
        entry: &ActivityEntry,
        net: &NetEvent,
        app: &str,
        destination: &str,
        incidents: &mut Vec<Incident>,
    ) {
        if is_high_churn_app(app) {
            return;
        }
        let known = self.baseline.knows_network(app, destination);
        let count = self.baseline.network_destination_count(app);
        if !known && count >= 5 {
            self.emit_novel_network(entry, net, app, destination, count, incidents);
        }
    }

    fn emit_novel_network(
        &mut self,
        entry: &ActivityEntry,
        net: &NetEvent,
        app: &str,
        destination: &str,
        known_count: usize,
        incidents: &mut Vec<Incident>,
    ) {
        let title = "Novel network destination".to_string();
        if self.should_emit(&title, app, Some(destination), entry.ts_ms) {
            incidents.push(Incident {
                ts_ms: entry.ts_ms,
                severity: Severity::Medium,
                title,
                pid: net.pid,
                comm: net.comm.clone(),
                path: Some(destination.to_string()),
                unit: entry.unit.clone(),
                details: json!({
                    "rule": "novel_network",
                    "destination": destination,
                    "known_destinations": known_count,
                    "app": app,
                    "unit": entry.unit,
                }),
            });
        }
    }

    fn should_emit(&mut self, title: &str, comm: &str, path: Option<&str>, now: u64) -> bool {
        let key = format!("{title}|{comm}|{}", path.unwrap_or_default());
        if let Some(last) = self.dedup.get(&key)
            && now.saturating_sub(*last) < DEDUP_WINDOW_MS
        {
            return false;
        }
        self.dedup.insert(key, now);
        true
    }

    fn home_for(&mut self, uid: u32) -> Option<PathBuf> {
        if let Some(home) = self.homes.get(&uid) {
            return home.clone();
        }
        let home = home_for_uid(uid);
        self.homes.insert(uid, home.clone());
        home
    }
}

fn app_key(entry: &ActivityEntry) -> String {
    entry
        .exe
        .as_deref()
        .filter(|exe| *exe != "(exited)")
        .map(str::to_string)
        .or_else(|| entry.nix.clone())
        .unwrap_or_else(|| event_identity(&entry.event).2)
}

fn is_browser_app(app: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "/usr/lib/firefox",
        "/usr/bin/firefox",
        "/opt/firefox",
        "/usr/lib/chromium",
        "/usr/bin/chromium",
        "/opt/google/chrome",
        "/opt/brave",
        "/usr/bin/brave",
        "/usr/lib/brave",
    ];
    PREFIXES.iter().any(|prefix| app.starts_with(prefix))
        || (app.starts_with("/nix/store/")
            && (app.contains("-firefox")
                || app.contains("-chromium")
                || app.contains("-google-chrome")
                || app.contains("-brave")))
}

fn is_bulk_noise_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    [
        "/.cache/",
        "/.thumbnails/",
        "/cache/",
        "/target/",
        "/node_modules/",
        "/.mozilla/",
        "/.config/chromium/",
        "/.config/google-chrome/",
        "/.local/share/trash/",
        "/tmp/",
        "/var/tmp/",
        "/var/cache/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn is_high_churn_app(app: &str) -> bool {
    if is_browser_app(app) {
        return true;
    }
    let app = app.to_ascii_lowercase();
    [
        "transmission",
        "qbittorrent",
        "deluge",
        "ktorrent",
        "aria2",
        "rtorrent",
        "thunar",
        "tumblerd",
        "tracker",
        "baloo",
        "cargo",
        "rustc",
        "nix-daemon",
        "nix-store",
        "node",
        "bun",
        "deno",
        "opencode",
    ]
    .iter()
    .any(|name| app.contains(name))
}

fn event_identity(event: &ObservedEvent) -> (u32, u32, String) {
    match event {
        ObservedEvent::Exec(event) => (event.pid, event.uid, event.comm.clone()),
        ObservedEvent::Exit(event) => (event.pid, event.uid, event.comm.clone()),
        ObservedEvent::Connect(event)
        | ObservedEvent::Accept(event)
        | ObservedEvent::Listen(event) => (event.pid, event.uid, event.comm.clone()),
        ObservedEvent::FileRead(event)
        | ObservedEvent::FileOpen(event)
        | ObservedEvent::FileWrite(event)
        | ObservedEvent::FileUnlink(event) => (event.pid, event.uid, event.comm.clone()),
        ObservedEvent::FileRename(event) => (event.pid, event.uid, event.comm.clone()),
        ObservedEvent::Traffic(summary) => (summary.pid, 0, summary.comm.clone()),
    }
}

fn home_for_uid(uid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        if fields[2].parse::<u32>().ok() == Some(uid) {
            return Some(PathBuf::from(fields[5]));
        }
    }
    None
}

fn classify_with_home(path: &str, home: Option<&Path>) -> Option<(&'static str, Severity)> {
    let path = Path::new(path);
    let home_relative = |relative: &str| {
        home.is_some_and(|home| path.starts_with(home.join(relative)))
            || path.to_string_lossy().contains(&format!("/{relative}/"))
    };

    if path.starts_with("/nix/store") {
        return Some(("Nix store", Severity::High));
    }
    if path.starts_with("/etc/shadow")
        || path.starts_with("/etc/sudoers")
        || path.starts_with("/etc/passwd")
    {
        return Some(("System credentials", Severity::High));
    }
    if path.starts_with("/etc/ssh") || path.starts_with("/root/.ssh") {
        return Some(("SSH", Severity::High));
    }
    if path.starts_with("/etc/systemd/system")
        || path.starts_with("/etc/systemd/user")
        || home_relative(".config/systemd/user")
    {
        return Some(("Persistence", Severity::High));
    }
    if home_relative(".ssh") {
        return Some(("SSH", Severity::High));
    }
    if home_relative(".gnupg") {
        return Some(("GnuPG", Severity::High));
    }
    if home_relative(".aws") {
        return Some(("AWS credentials", Severity::High));
    }
    if home_relative(".azure") {
        return Some(("Azure credentials", Severity::High));
    }
    if home_relative(".config/gcloud") {
        return Some(("GCloud credentials", Severity::High));
    }
    if home_relative(".kube") {
        return Some(("Kubernetes credentials", Severity::High));
    }
    if home_relative(".config/gh") {
        return Some(("GitHub CLI credentials", Severity::High));
    }
    if home_relative(".git-credentials") || home_relative(".netrc") {
        return Some(("Git credentials", Severity::High));
    }
    if home_relative(".password-store") || path.extension().is_some_and(|ext| ext == "kdbx") {
        return Some(("Password manager", Severity::High));
    }
    if home_relative(".config/autostart") || path.ends_with("authorized_keys") {
        return Some(("Persistence", Severity::Medium));
    }
    if home_relative(".bashrc")
        || home_relative(".zshrc")
        || home_relative(".profile")
        || home_relative(".bash_profile")
        || home_relative(".config/fish/config.fish")
    {
        return Some(("Shell startup", Severity::Medium));
    }

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let text = path.to_string_lossy();
    if (text.contains("/.mozilla/firefox/") || text.contains("/.config/google-chrome/"))
        && matches!(
            name,
            "logins.json" | "key4.db" | "key3.db" | "cookies.sqlite" | "Login Data" | "Cookies"
        )
    {
        return Some(("Browser credentials", Severity::High));
    }
    None
}

fn suspicious_execution(exe: &str, home: Option<&Path>) -> Option<&'static str> {
    if exe == "(exited)" {
        return None;
    }
    if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/run/user/") {
        return Some("temporary or writable runtime directory");
    }
    if let Some(home) = home {
        let path = Path::new(exe);
        if path.starts_with(home.join("Downloads")) {
            return Some("downloads directory");
        }
        if path.starts_with(home.join(".cache")) {
            return Some("browser/user cache");
        }
        if path.starts_with(home.join(".local/share/Trash")) {
            return Some("trash");
        }
    }
    None
}

fn is_public_destination(net: &NetEvent) -> bool {
    let ip = match net.family {
        electric_eye_core::event::AF_INET => IpAddr::V4(Ipv4Addr::new(
            net.addr[0],
            net.addr[1],
            net.addr[2],
            net.addr[3],
        )),
        electric_eye_core::event::AF_INET6 => IpAddr::V6(Ipv6Addr::from(net.addr)),
        _ => return false,
    };
    match ip {
        IpAddr::V4(ip) => !ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && (octets[0] & 0xfe) != 0xfc
        }
    }
}

#[cfg(test)]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ssh_and_browser_credentials() {
        let home = Path::new("/home/alice");
        assert_eq!(
            classify_with_home("/home/alice/.ssh/id_ed25519", Some(home)).map(|v| v.0),
            Some("SSH")
        );
        assert_eq!(
            classify_with_home(
                "/home/alice/.mozilla/firefox/x.default/logins.json",
                Some(home)
            )
            .map(|v| v.0),
            Some("Browser credentials")
        );
        assert_eq!(
            classify_with_home("/home/alice/notes.txt", Some(home)),
            None
        );
    }

    #[test]
    fn classifies_persistence_and_nix_store() {
        let home = Path::new("/home/alice");
        assert_eq!(
            classify_with_home("/home/alice/.config/systemd/user/evil.service", Some(home))
                .map(|v| v.0),
            Some("Persistence")
        );
        assert_eq!(
            classify_with_home("/nix/store/abc-evil/bin/evil", Some(home)).map(|v| v.0),
            Some("Nix store")
        );
    }

    #[test]
    fn dedup_suppresses_repeated_incidents() {
        let mut engine = AnomalyEngine::new();
        let now = now_ms();
        assert!(engine.should_emit("rule", "comm", Some("/tmp/x"), now));
        assert!(!engine.should_emit("rule", "comm", Some("/tmp/x"), now + 1000));
        assert!(engine.should_emit("rule", "comm", Some("/tmp/x"), now + DEDUP_WINDOW_MS + 1));
    }

    #[test]
    fn builtin_allowlist_covers_system_auth_reads() {
        let allowlist = Allowlist::load_default();
        assert!(allowlist.allows("sudo", "/etc/shadow"));
        assert!(allowlist.allows("unix_chkpwd", "/etc/passwd"));
        assert!(!allowlist.allows("bash", "/etc/shadow"));
        assert!(!allowlist.allows("sudo", "/home/alice/.ssh/id_rsa"));
    }

    #[test]
    fn baseline_tracks_paths_and_network_destinations() {
        let baseline = BaselineData::from_pairs(
            vec![(
                "firefox".into(),
                "/home/a/.mozilla/firefox/x/logins.json".into(),
            )],
            vec![
                ("firefox".into(), "1.1.1.1:443".into()),
                ("firefox".into(), "2.2.2.2:443".into()),
            ],
        );
        assert!(baseline.knows_path("firefox", "/home/a/.mozilla/firefox/x/logins.json"));
        assert!(!baseline.knows_path("firefox", "/home/a/.ssh/id_rsa"));
        assert!(baseline.knows_network("firefox", "1.1.1.1:443"));
        assert_eq!(baseline.network_destination_count("firefox"), 2);
    }

    #[test]
    fn engine_skips_allowlisted_credentials() {
        let mut engine =
            AnomalyEngine::with_context(BaselineData::default(), Allowlist::load_default());
        let entry = ActivityEntry {
            ts_ms: 1_000,
            event: ObservedEvent::FileRead(electric_eye_core::FileEvent {
                pid: 10,
                uid: 0,
                comm: "sudo".into(),
                path: "/etc/shadow".into(),
                kind: FileKind::Read,
                bytes: None,
                count: None,
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: None,
        };
        assert!(engine.observe(&entry).is_empty());
    }

    #[test]
    fn engine_flags_non_allowlisted_credentials() {
        let mut engine =
            AnomalyEngine::with_context(BaselineData::default(), Allowlist::load_default());
        let entry = ActivityEntry {
            ts_ms: 1_000,
            event: ObservedEvent::FileRead(electric_eye_core::FileEvent {
                pid: 10,
                uid: 1000,
                comm: "curl".into(),
                path: "/etc/shadow".into(),
                kind: FileKind::Read,
                bytes: None,
                count: None,
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: None,
        };
        assert_eq!(engine.observe(&entry).len(), 1);
    }

    #[test]
    fn browser_credential_writes_are_not_incidents() {
        let mut engine = AnomalyEngine::new();
        let entry = ActivityEntry {
            ts_ms: 1_000,
            event: ObservedEvent::FileWrite(electric_eye_core::FileEvent {
                pid: 10,
                uid: 1000,
                comm: "sqldb:c~lite #9".into(),
                path: "/home/alice/.mozilla/firefox/x/cookies.sqlite".into(),
                kind: FileKind::Write,
                bytes: Some(4096),
                count: Some(1),
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: Some("/usr/lib/firefox/firefox".into()),
        };
        assert!(engine.observe(&entry).is_empty());
    }

    #[test]
    fn cache_paths_do_not_trigger_bulk_mutation() {
        assert!(is_bulk_noise_path(
            "/home/alice/.cache/thumbnails/large/abc.png"
        ));
        assert!(!is_bulk_noise_path("/home/alice/Documents/report.pdf"));
        assert!(is_high_churn_app("transmission-gtk"));
        assert!(is_high_churn_app("/usr/lib/firefox/firefox"));
        assert!(!is_high_churn_app("/usr/bin/python3"));
    }
}
