use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use electric_eye_core::{FileKind, NetEvent, ObservedEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::ActivityEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    pub fn priority(self) -> &'static str {
        match self {
            Severity::Low => "5",
            Severity::Medium => "4",
            Severity::High => "3",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaselineData {
    paths: HashSet<(String, String)>,
    network: crate::bloom::BloomFilter,
    network_counts: HashMap<String, usize>,
}

/// Network baselines and deduplication keys use the IP:port endpoint without
/// the optional reverse-DNS label. The same destination must not look novel
/// merely because one observation had a hostname and another did not.
fn network_key(destination: &str) -> &str {
    destination
        .split_once(" (")
        .map_or(destination, |(endpoint, _)| endpoint)
}

impl BaselineData {
    #[cfg(test)]
    pub fn from_pairs(
        paths: impl IntoIterator<Item = (String, String)>,
        network: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self::from_pairs_with_capacity(paths, network, 65_536)
    }

    pub fn from_pairs_with_capacity(
        paths: impl IntoIterator<Item = (String, String)>,
        network: impl IntoIterator<Item = (String, String)>,
        capacity: usize,
    ) -> Self {
        let paths: HashSet<(String, String)> = paths.into_iter().collect();
        let mut filter = crate::bloom::BloomFilter::for_entries(capacity);
        let mut network_counts = HashMap::new();
        for (comm, destination) in network {
            let destination = network_key(&destination);
            if filter.contains(&comm, destination) {
                continue;
            }
            filter.insert(&comm, destination);
            *network_counts.entry(comm).or_insert(0) += 1;
        }
        Self {
            paths,
            network: filter,
            network_counts,
        }
    }

    pub fn knows_path(&self, comm: &str, path: &str) -> bool {
        self.paths.contains(&(comm.to_string(), path.to_string()))
    }

    pub fn knows_network(&self, comm: &str, destination: &str) -> bool {
        self.network.contains(comm, network_key(destination))
    }

    /// Learn a destination after the first observation so that only the first
    /// contact is reported as novel. Without this, a long-running daemon keeps
    /// re-reporting every destination first seen after startup. A Bloom filter
    /// keeps this state bounded even on hosts that contact many endpoints.
    pub fn learn_network(&mut self, comm: &str, destination: &str) {
        let destination = network_key(destination);
        if self.network.contains(comm, destination) {
            return;
        }
        self.network.insert(comm, destination);
        *self.network_counts.entry(comm.to_string()).or_insert(0) += 1;
    }

    pub fn network_destination_count(&self, comm: &str) -> usize {
        self.network_counts.get(comm).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<(String, String)>,
    identities: HashMap<String, crate::provenance::FileIdentity>,
    aliases: HashMap<String, Vec<String>>,
}

impl Allowlist {
    #[cfg(test)]
    pub fn load_default() -> Self {
        Self::load(&crate::config::RuleConfig::default())
    }

    pub fn load(config: &crate::config::RuleConfig) -> Self {
        let mut allowlist = Self::default();
        if config.builtin_auth_allowlist {
            for comm in [
                "unix_chkpwd",
                "sudo",
                "su",
                "login",
                "sshd",
                "systemd-userdbd",
                "pwck",
                "grpck",
                "chage",
                "passwd",
                "gpasswd",
                "systemd-tmpfiles",
                "systemd-tmpfile",
                "systemd-sysusers",
                "systemd-sysuser",
                "useradd",
                "usermod",
                "userdel",
                "groupadd",
                "groupmod",
                "groupdel",
            ] {
                for path in ["/etc/shadow", "/etc/gshadow"] {
                    allowlist.add(comm, path);
                }
            }
            for comm in ["sudo", "visudo"] {
                for path in ["/etc/sudoers", "/etc/sudoers.d"] {
                    allowlist.add(comm, path);
                }
            }
        }
        if config.builtin_noise_allowlist {
            // These identities routinely read credentials, logs, caches, and
            // network metadata as part of their normal operation. Their
            // activity remains visible in history; only rule incidents are
            // suppressed. Users can turn this off and add narrower entries.
            for comm in ["tailscaled", "thunar", "git", "cargo"] {
                allowlist.add(comm, "*");
            }
        }
        for rule in &config.allowlist {
            allowlist.add(&rule.application, &rule.subject_prefix);
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

    fn register(&mut self, name: &str) -> Vec<String> {
        let candidates = if Path::new(name).is_absolute() {
            vec![PathBuf::from(name)]
        } else {
            vec![
                Path::new("/usr/bin").join(name),
                Path::new("/usr/lib").join(name),
                Path::new("/usr/lib/ssh").join(name),
            ]
        };
        let mut paths = Vec::new();
        for path in candidates {
            let Ok(path) = path.canonicalize() else {
                continue;
            };
            if !trusted_path(&path) {
                continue;
            }
            if path.is_dir() {
                // Browser prefixes are usually package directories rather
                // than the executable itself (for example
                // /usr/lib/firefox/firefox). Register executable children so
                // the browser exemption can verify the actual binary.
                let Ok(entries) = std::fs::read_dir(&path) else {
                    continue;
                };
                let mut children: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
                children.sort();
                for child in children {
                    if !trusted_path(&child) {
                        continue;
                    }
                    let Ok(file) = crate::metadata::open_regular(&child, 512 * 1024 * 1024) else {
                        continue;
                    };
                    let Ok(metadata) = file.metadata() else {
                        continue;
                    };
                    use std::os::unix::fs::MetadataExt;
                    if metadata.mode() & 0o111 == 0 {
                        continue;
                    }
                    let child = child.to_string_lossy().into_owned();
                    self.identities.insert(
                        child.clone(),
                        crate::provenance::FileIdentity::from_metadata(&metadata),
                    );
                    paths.push(child);
                }
                continue;
            }
            let Ok(file) = crate::metadata::open_regular(&path, 512 * 1024 * 1024) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            let path = path.to_string_lossy().into_owned();
            self.identities.insert(
                path.clone(),
                crate::provenance::FileIdentity::from_metadata(&metadata),
            );
            paths.push(path);
        }
        self.aliases.insert(name.to_string(), paths.clone());
        paths
    }
    pub fn add(&mut self, application: &str, prefix: &str) {
        for path in self.register(application) {
            self.rules.push((path, prefix.to_string()));
        }
    }
    fn executable<'a>(&self, entry: &'a ActivityEntry) -> Option<&'a str> {
        let path = entry.exe.as_deref()?;
        let observed = entry.executable_identity?;
        (self.identities.get(path) == Some(&observed)).then_some(path)
    }
    fn matches_application(&self, application: &str, entry: &ActivityEntry) -> bool {
        let Some(path) = self.executable(entry) else {
            return false;
        };
        self.aliases
            .get(application)
            .is_some_and(|paths| paths.iter().any(|candidate| candidate == path))
    }
    #[cfg(test)]
    fn trust_fixture(&mut self, path: &str) -> crate::provenance::FileIdentity {
        let identity = crate::provenance::FileIdentity {
            device: 1,
            inode: 2,
        };
        self.identities.insert(path.into(), identity);
        self.aliases.insert(path.into(), vec![path.into()]);
        self.aliases.insert(
            Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            vec![path.into()],
        );
        identity
    }
    fn allows_entry(&self, entry: &ActivityEntry, subject: &str) -> bool {
        let Some(path) = self.executable(entry) else {
            return false;
        };
        self.rules.iter().any(|(allowed, prefix)| {
            allowed == path && (prefix == "*" || Path::new(subject).starts_with(prefix))
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Incident {
    pub ts_ms: u64,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<crate::api::ProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
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

pub struct AnomalyEngine {
    homes: crate::cache::Recent<Option<PathBuf>>,
    sensitive: crate::cache::Recent<VecDeque<(u64, String)>>,
    mutations: crate::cache::Recent<VecDeque<(u64, String)>>,
    trusted_ssh: crate::cache::Recent<Vec<String>>,
    known_hosts: crate::known_hosts::Cache,
    dedup: crate::cache::Recent<u64>,
    baseline: BaselineData,
    allowlist: Allowlist,
    network_allowlist: Vec<crate::config::NetworkAllowRule>,
    config: crate::config::RuleConfig,
    last_prune: u64,
    watermark: u64,
}

impl AnomalyEngine {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn with_context(baseline: BaselineData, allowlist: Allowlist) -> Self {
        Self::configured(baseline, allowlist, crate::config::RuleConfig::default())
    }
    pub fn configured(
        mut baseline: BaselineData,
        mut allowlist: Allowlist,
        config: crate::config::RuleConfig,
    ) -> Self {
        baseline.paths = baseline
            .paths
            .into_iter()
            .take(config.max_baseline_entries)
            .collect();
        // The network baseline is already a bounded Bloom filter built with
        // the configured capacity; it cannot be truncated further.
        for application in config
            .high_churn_apps
            .iter()
            .map(String::as_str)
            .chain(
                config
                    .network_allowlist
                    .iter()
                    .map(|rule| rule.application.as_str()),
            )
            .chain([
                "ssh",
                "/usr/lib/firefox/firefox",
                "/usr/lib/chromium/chromium",
                "/opt/google/chrome/chrome",
                "/opt/brave.com/brave/brave",
            ])
            .chain(config.browser_prefixes.iter().map(String::as_str))
        {
            if application != "*" {
                allowlist.register(application);
            }
        }
        Self {
            homes: crate::cache::Recent::new(config.max_actors),
            sensitive: crate::cache::Recent::new(config.max_actors),
            mutations: crate::cache::Recent::new(config.max_actors),
            trusted_ssh: crate::cache::Recent::new(config.max_actors),
            known_hosts: crate::known_hosts::Cache::default(),
            dedup: crate::cache::Recent::new(config.max_dedup_entries),
            baseline,
            allowlist,
            network_allowlist: config.network_allowlist.clone(),
            config,
            last_prune: 0,
            watermark: 0,
        }
    }
    pub fn prune(&mut self, now: u64) {
        self.watermark = self.watermark.max(now);
        if self.watermark.saturating_sub(self.last_prune) < self.config.prune_interval_ms {
            return;
        }
        self.last_prune = self.watermark;
        self.sensitive.expire_before(
            self.watermark
                .saturating_sub(self.config.sensitive_window_ms),
        );
        self.mutations
            .expire_before(self.watermark.saturating_sub(self.config.bulk_window_ms));
        self.trusted_ssh.expire_before(
            self.watermark
                .saturating_sub(self.config.sensitive_window_ms.max(300_000)),
        );
        self.dedup
            .expire_before(self.watermark.saturating_sub(self.config.dedup_window_ms));
    }
    fn classify(&self, path: &str, home: Option<&Path>) -> Option<(String, Severity)> {
        self.config
            .sensitive_paths
            .iter()
            .find(|r| Path::new(path).starts_with(&r.prefix))
            .map(|r| (r.category.clone(), r.severity))
            .or_else(|| {
                self.config
                    .builtin_sensitive_paths
                    .then(|| classify_with_home(path, home))
                    .flatten()
                    .map(|(c, s)| (c.into(), s))
            })
    }
    pub fn observe(&mut self, entry: &ActivityEntry) -> Vec<Incident> {
        self.prune(entry.ts_ms);
        let actor = timeline_key(entry);
        if matches!(entry.event, ObservedEvent::Exit(_) | ObservedEvent::Exec(_)) {
            self.sensitive.remove(&actor);
            self.mutations.remove(&actor);
        }
        if let ObservedEvent::Exec(_) = &entry.event
            && self.allowlist.matches_application("ssh", entry)
            && let Some(info) = &entry.process_info
        {
            let mut hosts: Vec<String> = Vec::new();
            if self.config.known_hosts_allow
                && let Some((host, port)) = crate::known_hosts::destination(&info.argv)
            {
                let (_, uid, _) = event_identity(&entry.event);
                let home = self.home_for(uid);
                if self.known_hosts.is_known(home.as_deref(), &host, port) {
                    hosts.push(host);
                }
            }
            hosts.sort();
            hosts.dedup();
            if !hosts.is_empty() {
                self.trusted_ssh.insert(actor.clone(), entry.ts_ms, hosts);
            }
        }
        if matches!(entry.event, ObservedEvent::Exit(_)) {
            self.trusted_ssh.remove(&actor);
        }
        let mut incidents = Vec::new();
        if entry.syscall_result.is_some_and(|result| result < 0)
            || matches!(
                entry.path_resolution.as_deref(),
                Some("unresolved" | "lexical")
            )
        {
            return incidents;
        }
        self.observe_paths(entry, &mut incidents);
        self.observe_exec(entry, &mut incidents);
        self.observe_network(entry, &mut incidents);
        for incident in &mut incidents {
            incident.id = incident_id();
            incident.process = entry.process.clone();
            incident.exe = entry.exe.clone();
        }
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
        let actor = timeline_key(entry);
        if self.allowlist.matches_application("ssh", entry)
            && self.trusted_ssh.get(&actor).is_some()
        {
            return;
        }
        let home = self.home_for(uid);
        let now = entry.ts_ms;
        let directory_listing = matches!(&entry.event, ObservedEvent::FileRead(_))
            || matches!(
                &entry.event,
                ObservedEvent::FileOpen(file)
                    if matches!(file.kind, FileKind::Read | FileKind::Open)
            );
        let mut categories = Vec::new();
        let mutation = matches!(
            &entry.event,
            ObservedEvent::FileUnlink(_) | ObservedEvent::FileRename(_)
        ) || matches!(&entry.event, ObservedEvent::FileWrite(e) if e.kind==FileKind::Write)
            || matches!(&entry.event, ObservedEvent::FileOpen(e) if e.kind==FileKind::Truncate
            );

        for path in &paths {
            if self.allowlist.allows_entry(entry, path) {
                continue;
            }
            let known = self.baseline.knows_path(&app, path);
            if self.config.bulk_mutation && mutation && !is_bulk_noise_path(path, &self.config) {
                let window =
                    self.mutations
                        .get_or_insert_with(actor.clone(), self.watermark, VecDeque::new);
                push_bounded(
                    window,
                    (now, (*path).to_string()),
                    self.config.max_events_per_actor,
                );
            }
            if let Some((category, severity)) = self.classify(path, home.as_deref()) {
                // Listing a sensitive directory is metadata access, not reading
                // the credentials inside it. Only file-level access is classified.
                if directory_listing && path_is_directory(path) {
                    continue;
                }
                if category == "Browser credentials"
                    && self
                        .allowlist
                        .executable(entry)
                        .is_some_and(|path| is_browser_app(path, &self.config))
                {
                    continue;
                }
                categories.push(category.clone());
                let title = format!("Sensitive path access: {category}");
                if self.config.sensitive_path
                    && !known
                    && self.should_emit(&title, &app, Some(category.as_str()), now)
                {
                    incidents.push(Incident {
                        id: String::new(),
                        process: None,
                        exe: None,
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
            }
        }

        if !categories.is_empty() {
            let window =
                self.sensitive
                    .get_or_insert_with(actor.clone(), self.watermark, VecDeque::new);
            for category in categories {
                push_bounded(window, (now, category), self.config.max_events_per_actor);
            }
            while window
                .front()
                .is_some_and(|(ts, _)| now.saturating_sub(*ts) > self.config.sensitive_window_ms)
            {
                window.pop_front();
            }
            let distinct: HashSet<String> = window
                .iter()
                .map(|(_, category)| category.clone())
                .collect();
            if self.config.credential_sweep
                && distinct.len() >= self.config.credential_category_threshold
            {
                let title = "Credential sweep across multiple sensitive categories".to_string();
                if self.should_emit(&title, &app, None, now) {
                    incidents.push(Incident {
                        id: String::new(),
                        process: None,
                        exe: None,
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

        self.observe_bulk(entry, &app, &actor, home.as_deref(), incidents);
    }

    fn observe_bulk(
        &mut self,
        entry: &ActivityEntry,
        app: &str,
        actor: &str,
        home: Option<&Path>,
        incidents: &mut Vec<Incident>,
    ) {
        let (pid, _, comm) = event_identity(&entry.event);
        let now = entry.ts_ms;
        let unit = entry.unit.as_deref();
        if !self.config.bulk_mutation || self.high_churn_entry(entry) {
            return;
        }
        let (unique_count, files, files_truncated, scope, severity, fresh_output) = {
            let Some(window) = self.mutations.get_mut(actor) else {
                return;
            };
            while window
                .front()
                .is_some_and(|(ts, _)| now.saturating_sub(*ts) > self.config.bulk_window_ms)
            {
                window.pop_front();
            }
            let unique: HashSet<&str> = window.iter().map(|(_, path)| path.as_str()).collect();
            let (scope, severity) = bulk_scope(unique.iter().copied(), home);
            let fresh_output = severity == Severity::Low
                && mostly_recent_creations(unique.iter().copied(), now, self.config.bulk_window_ms);
            let mut files: Vec<String> = unique.iter().map(|path| (*path).to_string()).collect();
            files.sort();
            let truncated = files.len() > 32;
            files.truncate(32);
            (
                unique.len(),
                files,
                truncated,
                scope,
                severity,
                fresh_output,
            )
        };
        if unique_count >= self.config.bulk_file_threshold && !fresh_output {
            let title = "Bulk filesystem mutation".to_string();
            if self.should_emit(&title, app, None, now) {
                incidents.push(Incident {
                    id: String::new(),
                    process: None,
                    exe: None,
                    ts_ms: now,
                    severity,
                    title,
                    pid,
                    comm: comm.to_string(),
                    path: None,
                    unit: unit.map(str::to_string),
                    details: json!({
                        "rule": "bulk_mutation",
                        "scope": scope,
                        "files_in_window": unique_count,
                        "files": files,
                        "files_truncated": files_truncated,
                        "window_seconds": self.config.bulk_window_ms / 1000,
                    }),
                });
            }
        }
    }

    fn observe_exec(&mut self, entry: &ActivityEntry, incidents: &mut Vec<Incident>) {
        if !self.config.suspicious_execution {
            return;
        }
        let ObservedEvent::Exec(event) = &entry.event else {
            return;
        };
        let exe = event.exe.display().to_string();
        if self.allowlist.allows_entry(entry, &exe) {
            return;
        }
        let Some(reason) =
            suspicious_execution(&exe, self.home_for(event.uid).as_deref(), &self.config)
        else {
            return;
        };
        let title = "Executable launched from a suspicious location".to_string();
        if self.should_emit(&title, &event.comm, Some(&exe), entry.ts_ms) {
            incidents.push(Incident {
                id: String::new(),
                process: None,
                exe: None,
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

    fn network_allowed(
        &self,
        entry: &ActivityEntry,
        net: &NetEvent,
        direction: crate::config::NetworkDirection,
    ) -> bool {
        self.network_allowlist.iter().any(|rule| {
            (rule.direction == crate::config::NetworkDirection::Both || rule.direction == direction)
                && (rule.application == "*"
                    || self.allowlist.matches_application(&rule.application, entry))
                && destination_matches(&rule.destination, net)
        })
    }

    fn observe_incoming(
        &mut self,
        entry: &ActivityEntry,
        net: &NetEvent,
        app: &str,
        incidents: &mut Vec<Incident>,
    ) {
        if !self.config.incoming_connections
            || net.local_port == 0
            || net.addr == [0; 16]
            || self.high_churn_entry(entry)
        {
            return;
        }
        let remote_ip = net.addr_string();
        let Ok(ip) = remote_ip.parse::<IpAddr>() else {
            return;
        };
        if ip.is_unspecified() {
            return;
        }
        let source_scope = if crate::net_context::is_tailscale_ip(ip) {
            "tailscale"
        } else if is_loopback_ip(ip) {
            "same_machine"
        } else if is_private_ip(ip) {
            "local_network"
        } else {
            "remote"
        };
        if matches!(source_scope, "same_machine" | "local_network")
            && !self.config.incoming_local_connections
        {
            return;
        }
        let source_label = match source_scope {
            "tailscale" => "Tailscale",
            "same_machine" => "same machine",
            "local_network" => "local network",
            _ => "remote",
        };
        let service = service_name(net.local_port);
        let title = format!("Incoming connection: {service} [{source_label}]");
        let subject = format!("{}:{}", net.local_port, remote_ip);
        if !self.should_emit(&title, app, Some(&subject), entry.ts_ms) {
            return;
        }
        incidents.push(Incident {
            id: String::new(),
            process: None,
            exe: None,
            ts_ms: entry.ts_ms,
            // A public remote source is materially more exposed than a local,
            // same-machine, or Tailscale peer.
            severity: if source_scope == "remote" {
                Severity::High
            } else {
                Severity::Medium
            },
            title,
            pid: net.pid,
            comm: net.comm.clone(),
            path: Some(net.remote_endpoint()),
            unit: entry.unit.clone(),
            details: json!({
                "rule": "incoming_connection",
                "direction": "inbound",
                "source_scope": source_scope,
                "source_label": source_label,
                "service": service,
                "local_port": net.local_port,
                "remote": net.remote_endpoint(),
                "unit": entry.unit,
            }),
        });
    }

    fn observe_network(&mut self, entry: &ActivityEntry, incidents: &mut Vec<Incident>) {
        let net = match &entry.event {
            ObservedEvent::Connect(event) => event,
            ObservedEvent::Accept(event) => event,
            _ => return,
        };
        let actor = timeline_key(entry);
        if self.allowlist.matches_application("ssh", entry)
            && self.trusted_ssh.get(&actor).is_some_and(|hosts| {
                net.hostname.as_deref().is_some_and(|hostname| {
                    let hostname = hostname.to_ascii_lowercase();
                    hosts.contains(&hostname)
                })
            })
        {
            return;
        }
        let app = app_key(entry);
        let destination = net.remote_endpoint();
        let destination_scope = net_ip(net)
            .map(crate::net_context::address_scope)
            .unwrap_or("unknown");
        let direction = if matches!(&entry.event, ObservedEvent::Accept(_)) {
            crate::config::NetworkDirection::Inbound
        } else {
            crate::config::NetworkDirection::Outbound
        };
        if self.network_allowed(entry, net, direction) {
            return;
        }
        if matches!(&entry.event, ObservedEvent::Accept(_)) {
            self.observe_incoming(entry, net, &app, incidents);
            return;
        }
        if self.allowlist.allows_entry(entry, &destination) {
            return;
        }
        // MagicDNS is the local Tailscale resolver, not an application
        // destination. Other Tailscale peers are handled explicitly below.
        if destination_scope == "tailscale-magicdns" {
            return;
        }
        let tailscale_peer = destination_scope == "tailscale";
        if !is_public_destination(net) && !tailscale_peer {
            return;
        }
        let is_connect = matches!(&entry.event, ObservedEvent::Connect(_));
        if !is_connect {
            return;
        }

        let recent = {
            let Some(window) = self.sensitive.get(&timeline_key(entry)) else {
                self.maybe_novel_network(entry, &app, &destination, destination_scope, incidents);
                return;
            };
            window
                .iter()
                .rev()
                .find(|(ts, _)| entry.ts_ms.saturating_sub(*ts) <= self.config.sensitive_window_ms)
                .map(|(ts, category)| (*ts, category.clone()))
        };
        if let Some((ts, category)) = recent.filter(|_| self.config.sensitive_egress) {
            let title = "Sensitive path access followed by network egress".to_string();
            if self.should_emit(&title, &app, None, entry.ts_ms) {
                incidents.push(Incident {
                    id: String::new(),
                    process: None,
                    exe: None,
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
                        "destination_scope": destination_scope,
                        "unit": entry.unit,
                    }),
                });
            }
            return;
        }

        self.maybe_novel_network(entry, &app, &destination, destination_scope, incidents);
    }

    fn maybe_novel_network(
        &mut self,
        entry: &ActivityEntry,
        app: &str,
        destination: &str,
        destination_scope: &str,
        incidents: &mut Vec<Incident>,
    ) {
        if !self.config.novel_network || self.high_churn_entry(entry) {
            return;
        }
        let known = self.baseline.knows_network(app, destination);
        let count = self.baseline.network_destination_count(app);
        if !known && count >= self.config.novel_network_min_destinations {
            self.emit_novel_network(entry, app, destination, destination_scope, count, incidents);
        }
        // A destination is novel only on first contact. Recording it here also
        // covers destinations observed while the daemon is running, not just
        // the startup baseline loaded from history.
        self.baseline.learn_network(app, destination);
    }

    fn emit_novel_network(
        &mut self,
        entry: &ActivityEntry,
        app: &str,
        destination: &str,
        destination_scope: &str,
        known_count: usize,
        incidents: &mut Vec<Incident>,
    ) {
        let (title, severity) = if destination_scope == "tailscale" {
            ("Novel Tailscale destination", Severity::Low)
        } else {
            ("Novel network destination", Severity::Medium)
        };
        if self.should_emit(title, app, Some(network_key(destination)), entry.ts_ms) {
            let (pid, _, comm) = event_identity(&entry.event);
            incidents.push(Incident {
                id: String::new(),
                process: None,
                exe: None,
                ts_ms: entry.ts_ms,
                severity,
                title: title.to_string(),
                pid,
                comm,
                path: Some(destination.to_string()),
                unit: entry.unit.clone(),
                details: json!({
                    "rule": "novel_network",
                    "destination": destination,
                    "destination_scope": destination_scope,
                    "known_destinations": known_count,
                    "app": app,
                    "unit": entry.unit,
                }),
            });
        }
    }

    /// High-churn suppression is a noise policy, not a trust boundary. Match
    /// the observed executable and comm directly so a missing allowlist
    /// registration (for example `transmission-gtk` without a `transmission`
    /// symlink) cannot turn a P2P client into a flood of novel destinations.
    fn high_churn_entry(&self, entry: &ActivityEntry) -> bool {
        let exe = entry.exe.as_deref().unwrap_or_default();
        let (_, _, comm) = event_identity(&entry.event);
        is_high_churn_app(exe, &self.config) || is_high_churn_app(&comm, &self.config)
    }

    fn should_emit(&mut self, title: &str, comm: &str, path: Option<&str>, now: u64) -> bool {
        let key = format!("{title}|{comm}|{}", path.unwrap_or_default());
        if let Some(last) = self.dedup.get(&key)
            && now.saturating_sub(*last) < self.config.dedup_window_ms
        {
            return false;
        }
        self.dedup.insert(key, self.watermark.max(now), now);
        true
    }

    fn home_for(&mut self, uid: u32) -> Option<PathBuf> {
        if let Some(home) = self.homes.get(&uid.to_string()) {
            return home.clone();
        }
        let home = home_for_uid(uid);
        self.homes
            .insert(uid.to_string(), self.watermark, home.clone());
        home
    }
}

fn incident_id() -> String {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| {
            format!(
                "{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
                SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        })
}
fn timeline_key(entry: &ActivityEntry) -> String {
    match &entry.process {
        Some(p) => format!("{}:{}:{}", p.boot_id, p.pid, p.start_ns),
        None => format!("{}:{}", event_identity(&entry.event).0, app_key(entry)),
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

fn trusted_path(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    path.ancestors().all(|ancestor| {
        std::fs::metadata(ancestor)
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o022 == 0)
    })
}

pub(crate) fn is_browser_app(app: &str, config: &crate::config::RuleConfig) -> bool {
    config
        .browser_prefixes
        .iter()
        .any(|prefix| Path::new(app).starts_with(prefix))
        || app.starts_with("/nix/store/")
            && config
                .browser_nix_names
                .iter()
                .any(|name| app.contains(name))
}
fn is_bulk_noise_path(path: &str, config: &crate::config::RuleConfig) -> bool {
    if crate::auto_noise::looks_generated(path) {
        return true;
    }
    let path = path.to_ascii_lowercase();
    config
        .bulk_noise_paths
        .iter()
        .any(|marker| path.contains(&marker.to_ascii_lowercase()))
}
pub(crate) fn bulk_scope<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    home: Option<&Path>,
) -> (&'static str, Severity) {
    let parents: Vec<std::path::PathBuf> = paths
        .into_iter()
        .filter_map(|path| Path::new(path).parent().map(Path::to_path_buf))
        .collect();
    if parents.is_empty() {
        return ("unknown", Severity::Medium);
    }
    let common = common_parent(&parents);
    if common == Path::new("/") {
        return ("filesystem_wide", Severity::High);
    }
    if let Some(home) = home {
        if common == home {
            return ("home_root", Severity::High);
        }
        if common.starts_with(home) {
            return ("single_directory", Severity::Low);
        }
    }
    if common.starts_with("/etc")
        || common.starts_with("/usr")
        || common.starts_with("/boot")
        || common.starts_with("/root")
    {
        return ("system_paths", Severity::High);
    }
    if common.starts_with("/var") || common.starts_with("/opt") || common.starts_with("/srv") {
        return if common.components().count() >= 3 {
            ("single_directory", Severity::Low)
        } else {
            ("system_paths", Severity::High)
        };
    }
    if common.components().count() >= 3 {
        ("single_directory", Severity::Low)
    } else {
        ("multiple_directories", Severity::Medium)
    }
}

/// A single-directory burst that mostly creates new files is build output,
/// screen captures, generated caches, or similar work product, not a bulk
/// mutation of existing data. Birth times are unavailable on some filesystems;
/// in that case keep the existing conservative behavior.
fn mostly_recent_creations<'a>(
    paths: impl Iterator<Item = &'a str>,
    now: u64,
    window_ms: u64,
) -> bool {
    let cutoff = now.saturating_sub(window_ms);
    let mut total = 0usize;
    let mut recent = 0usize;
    for path in paths {
        total += 1;
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            continue;
        };
        let Ok(created) = metadata.created() else {
            continue;
        };
        let Ok(created) = created.duration_since(std::time::UNIX_EPOCH) else {
            continue;
        };
        if created.as_millis() as u64 >= cutoff {
            recent += 1;
        }
    }
    total > 0 && recent.saturating_mul(10) >= total.saturating_mul(9)
}

fn common_parent(paths: &[std::path::PathBuf]) -> std::path::PathBuf {
    let mut prefix = std::path::PathBuf::new();
    for component in paths[0].components() {
        let candidate = prefix.join(component.as_os_str());
        if paths.iter().all(|path| path.starts_with(&candidate)) {
            prefix = candidate;
        } else {
            break;
        }
    }
    prefix
}

pub(crate) fn is_high_churn_app(app: &str, config: &crate::config::RuleConfig) -> bool {
    is_browser_app(app, config)
        || config.high_churn_apps.iter().any(|name| {
            let executable = app.rsplit('/').next().unwrap_or(app).to_ascii_lowercase();
            let name = name.to_ascii_lowercase();
            executable == name || executable.starts_with(&format!("{name}-"))
        })
}
fn push_bounded<T>(window: &mut VecDeque<T>, value: T, limit: usize) {
    while window.len() >= limit {
        window.pop_front();
    }
    window.push_back(value);
}
impl Default for AnomalyEngine {
    fn default() -> Self {
        Self::configured(
            BaselineData::default(),
            Allowlist::default(),
            crate::config::RuleConfig::default(),
        )
    }
}

fn event_identity(event: &ObservedEvent) -> (u32, u32, String) {
    match event {
        ObservedEvent::Exec(event) | ObservedEvent::Fork(event) => {
            (event.pid, event.uid, event.comm.clone())
        }
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

fn path_is_directory(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn classify_with_home(path: &str, home: Option<&Path>) -> Option<(&'static str, Severity)> {
    // known_hosts contains public host keys, not credentials. curl and other
    // clients read it during normal startup even for non-SSH URLs.
    if path.ends_with("/.ssh/known_hosts")
        || path.ends_with("/.ssh/known_hosts.old")
        || path.ends_with("/.ssh/known_hosts2")
    {
        return None;
    }
    let path = Path::new(path);
    let cross_home = path
        .strip_prefix("/home")
        .ok()
        .and_then(|rest| {
            let mut components = rest.components();
            components.next()?;
            Some(components.as_path())
        })
        .or_else(|| path.strip_prefix("/root").ok());
    let home_relative = |relative: &str| {
        home.is_some_and(|home| path.starts_with(home.join(relative)))
            || cross_home.is_some_and(|rest| rest.starts_with(relative))
    };

    if path.starts_with("/nix/store") {
        return Some(("Nix store", Severity::High));
    }
    if crate::credentials::SYSTEM
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return Some(("System credentials", Severity::High));
    }
    if path.starts_with("/etc/ssh/") {
        // moduli, ssh_config, sshd_config and public host keys are not
        // credentials. Only private host keys belong in the credential rule.
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if name.starts_with("ssh_host_") && name.contains("_key") && !name.ends_with(".pub") {
            return Some(("SSH", Severity::High));
        }
        return None;
    }
    if path.starts_with("/root/.ssh") {
        return Some(("SSH", Severity::High));
    }
    if path.starts_with("/etc/systemd/system")
        || path.starts_with("/etc/systemd/user")
        || home_relative(".config/systemd/user")
    {
        return Some(("Persistence", Severity::High));
    }
    if home_relative(".ssh") {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if name.ends_with(".pub") {
            return None;
        }
        return Some(("SSH", Severity::High));
    }
    if let Some((_, category)) = crate::credentials::HOME
        .iter()
        .find(|(relative, _)| home_relative(relative))
    {
        return Some((category, Severity::High));
    }
    if path.extension().is_some_and(|ext| ext == "kdbx") {
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
    if crate::credentials::BROWSERS
        .iter()
        .any(|browser| text.contains(&format!("/{browser}/")))
        && crate::credentials::BROWSER_FILES.contains(&name)
    {
        return Some(("Browser credentials", Severity::High));
    }
    None
}

fn suspicious_execution(
    exe: &str,
    home: Option<&Path>,
    config: &crate::config::RuleConfig,
) -> Option<String> {
    if config
        .suspicious_prefixes
        .iter()
        .any(|prefix| Path::new(exe).starts_with(prefix))
    {
        return Some("configured writable/runtime location".into());
    }
    if let Some(home) = home
        && config
            .suspicious_home_paths
            .iter()
            .any(|relative| Path::new(exe).starts_with(home.join(relative)))
    {
        return Some("configured user writable location".into());
    }
    None
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|ip| ip.is_private() || ip.is_link_local() || ip.is_loopback())
        }
    }
}

fn service_name(port: u16) -> String {
    match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        9200 => "Elasticsearch",
        _ => return format!("port {port}"),
    }
    .into()
}

fn destination_matches(pattern: &str, net: &NetEvent) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let target = net.addr_string();
    if let Some((base, prefix)) = pattern.split_once('/') {
        let (Ok(ip), Ok(base), Ok(prefix)) = (
            target.parse::<IpAddr>(),
            base.parse::<IpAddr>(),
            prefix.parse::<u32>(),
        ) else {
            return false;
        };
        return ip_in_cidr(ip, base, prefix);
    }
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return target.parse::<IpAddr>().ok() == Some(ip);
    }
    let host = net
        .hostname
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn ip_in_cidr(ip: IpAddr, base: IpAddr, prefix: u32) -> bool {
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(base) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(base) & mask
        }
        _ => false,
    }
}

fn net_ip(net: &NetEvent) -> Option<IpAddr> {
    match net.family {
        electric_eye_core::event::AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            net.addr[0],
            net.addr[1],
            net.addr[2],
            net.addr[3],
        ))),
        electric_eye_core::event::AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(net.addr))),
        _ => None,
    }
}

fn is_public_destination(net: &NetEvent) -> bool {
    let Some(ip) = net_ip(net) else {
        return false;
    };
    if crate::net_context::is_tailscale_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_unspecified()
                    && !ip.is_broadcast()
                    && !ip.is_multicast();
            }
            let octets = ip.octets();
            !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
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
        assert_eq!(
            classify_with_home("/tmp/unrelated/.aws/credentials", Some(home)),
            None,
            "temporary directories must not look like credential stores"
        );
        assert_eq!(
            classify_with_home("/home/bob/.aws/credentials", Some(home)).map(|v| v.0),
            Some("AWS credentials")
        );
        assert_eq!(
            classify_with_home("/home/alice/.ssh/id_ed25519.pub", Some(home)),
            None
        );
        assert_eq!(classify_with_home("/etc/passwd", None), None);
        assert_eq!(
            classify_with_home("/etc/shadow", None).map(|v| v.0),
            Some("System credentials")
        );
        assert_eq!(classify_with_home("/etc/ssh/moduli", None), None);
        assert_eq!(classify_with_home("/etc/ssh/ssh_config", None), None);
        assert_eq!(
            classify_with_home("/etc/ssh/ssh_host_ed25519_key", None).map(|v| v.0),
            Some("SSH")
        );
        assert_eq!(
            classify_with_home("/home/alice/.ssh/known_hosts", Some(home)),
            None
        );
        assert_eq!(
            classify_with_home("/home/alice/.ssh/known_hosts.old", Some(home)),
            None
        );
        assert_eq!(
            classify_with_home("/home/alice/.config/gh/hosts.yml", Some(home)).map(|v| v.0),
            Some("GitHub CLI credentials")
        );
        assert_eq!(
            classify_with_home("/home/alice/.config/gh/config.yml", Some(home)),
            None,
            "gh preferences do not contain credentials"
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
        assert!(engine.should_emit(
            "rule",
            "comm",
            Some("/tmp/x"),
            now + engine.config.dedup_window_ms + 1
        ));
    }

    #[test]
    fn builtin_exemptions_are_bound_to_protected_executable_files() {
        let allowlist = Allowlist::load_default();
        for (path, prefix) in &allowlist.rules {
            assert!(Path::new(path).is_absolute());
            assert!(allowlist.identities.contains_key(path));
            let identity =
                crate::provenance::FileIdentity::from_metadata(&std::fs::metadata(path).unwrap());
            assert_eq!(allowlist.identities[path], identity);
            assert!(!prefix.is_empty());
        }
        let disabled = crate::config::RuleConfig {
            builtin_auth_allowlist: false,
            builtin_noise_allowlist: false,
            ..Default::default()
        };
        let allowlist = Allowlist::load(&disabled);
        assert!(allowlist.rules.is_empty());
    }

    #[test]
    fn grpck_is_a_builtin_auth_exemption() {
        if !Path::new("/usr/bin/grpck").exists() {
            return;
        }
        let allowlist = Allowlist::load_default();
        assert!(
            allowlist
                .rules
                .iter()
                .any(|(path, prefix)| { path == "/usr/bin/grpck" && prefix == "/etc/gshadow" })
        );
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
            executable_identity: None,
            ts_ms: 1_000,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: None,
            path_resolution: None,
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
        let mut entry = entry;
        entry.exe = Some("/usr/bin/sudo".into());
        entry.executable_identity = Some(engine.allowlist.trust_fixture("/usr/bin/sudo"));
        engine
            .allowlist
            .rules
            .push(("/usr/bin/sudo".into(), "/etc/shadow".into()));
        assert!(engine.observe(&entry).is_empty());
    }

    #[test]
    fn engine_flags_non_allowlisted_credentials() {
        let mut engine =
            AnomalyEngine::with_context(BaselineData::default(), Allowlist::load_default());
        let entry = ActivityEntry {
            executable_identity: None,
            ts_ms: 1_000,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: None,
            path_resolution: None,
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
        for exe in [
            "/usr/lib/firefox/firefox",
            "/usr/lib/firefox-developer-edition/firefox",
        ] {
            let mut engine = AnomalyEngine::new();
            let mut entry = ActivityEntry {
                executable_identity: None,
                ts_ms: 1_000,
                syscall_result: None,
                event_id: None,
                process_info: None,
                application: None,
                process: None,
                path_resolution: None,
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
                exe: Some(exe.into()),
            };
            entry.executable_identity = Some(engine.allowlist.trust_fixture(exe));
            assert!(engine.observe(&entry).is_empty(), "{exe}");
        }
    }

    #[test]
    fn browser_directory_prefixes_register_the_actual_binary() {
        for exe in [
            "/usr/lib/firefox/firefox",
            "/usr/lib/firefox-developer-edition/firefox",
        ] {
            let Ok(metadata) = std::fs::metadata(exe) else {
                continue;
            };
            let mut engine = AnomalyEngine::new();
            let entry = ActivityEntry {
                executable_identity: Some(crate::provenance::FileIdentity::from_metadata(
                    &metadata,
                )),
                ts_ms: 0,
                syscall_result: None,
                event_id: None,
                process_info: None,
                application: None,
                process: None,
                path_resolution: None,
                event: ObservedEvent::FileWrite(electric_eye_core::FileEvent {
                    pid: 10,
                    uid: 1000,
                    comm: "firefox".into(),
                    path: "/home/archie/.mozilla/firefox/test.default/cookies.sqlite".into(),
                    kind: FileKind::Write,
                    bytes: Some(4096),
                    count: Some(1),
                }),
                unit: None,
                nix: None,
                parent: None,
                exe: Some(exe.into()),
            };
            assert_eq!(engine.allowlist.executable(&entry), Some(exe), "{exe}");
            assert!(engine.observe(&entry).is_empty(), "{exe}");
        }
    }

    #[test]
    fn cache_paths_do_not_trigger_bulk_mutation() {
        assert!(is_bulk_noise_path(
            "/home/alice/.cache/thumbnails/large/abc.png",
            &crate::config::RuleConfig::default()
        ));
        assert!(!is_bulk_noise_path(
            "/home/alice/Documents/report.pdf",
            &crate::config::RuleConfig::default()
        ));
        assert!(is_high_churn_app(
            "transmission-gtk",
            &crate::config::RuleConfig::default()
        ));
        assert!(is_high_churn_app(
            "/usr/lib/firefox/firefox",
            &crate::config::RuleConfig::default()
        ));
        assert!(is_high_churn_app(
            "/usr/lib/firefox-developer-edition/firefox",
            &crate::config::RuleConfig::default()
        ));
        for app in ["steam", "steamwebhelper", "spotify", "yt-dlp", "youtube-dl"] {
            assert!(
                is_high_churn_app(app, &crate::config::RuleConfig::default()),
                "{app}"
            );
        }
        assert!(!is_high_churn_app(
            "/usr/bin/python3",
            &crate::config::RuleConfig::default()
        ));
    }
}

#[cfg(test)]
mod correlation_regressions {
    use super::*;
    use electric_eye_core::{FileEvent, TrafficSummary};
    fn file(path: &str, kind: FileKind) -> ActivityEntry {
        let e = FileEvent {
            pid: 123,
            uid: 1000,
            comm: "test-app".into(),
            path: path.into(),
            kind,
            bytes: Some(1),
            count: Some(1),
        };
        ActivityEntry {
            executable_identity: None,
            ts_ms: 1_000_000,
            syscall_result: None,
            event_id: None,
            process_info: None,
            application: None,
            process: Some(crate::api::ProcessIdentity {
                pid: 123,
                start_ns: 1,
                boot_id: "boot".into(),
            }),
            path_resolution: Some("kernel".into()),
            event: if kind == FileKind::Read {
                ObservedEvent::FileRead(e)
            } else {
                ObservedEvent::FileWrite(e)
            },
            unit: None,
            nix: None,
            parent: None,
            exe: Some("/opt/test-app".into()),
        }
    }
    fn network() -> ActivityEntry {
        let mut e = file("", FileKind::Read);
        e.event = ObservedEvent::Connect(NetEvent {
            pid: 123,
            uid: 1000,
            comm: "test-app".into(),
            family: 2,
            addr: [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            local_port: 1234,
            remote_port: 443,
            hostname: None,
            fd: None,
        });
        e
    }
    #[test]
    fn known_credentials_still_feed_sweep_and_egress() {
        let paths = [
            "/root/.ssh/key",
            "/root/.aws/credentials",
            "/root/.gnupg/key",
        ];
        let baseline = BaselineData::from_pairs(
            paths
                .iter()
                .map(|p| ("/opt/test-app".into(), p.to_string())),
            [],
        );
        let mut engine = AnomalyEngine::with_context(baseline, Allowlist::default());
        let mut incidents = Vec::new();
        for path in paths {
            incidents.extend(engine.observe(&file(path, FileKind::Read)));
        }
        incidents.extend(engine.observe(&network()));
        assert!(
            !incidents
                .iter()
                .any(|i| i.details["rule"] == "sensitive_path")
        );
        assert!(
            incidents
                .iter()
                .any(|i| i.details["rule"] == "credential_sweep")
        );
        assert!(
            incidents
                .iter()
                .any(|i| i.details["rule"] == "sensitive_egress")
        );
        assert!(
            incidents
                .iter()
                .all(|i| !i.id.is_empty() && i.process.is_some() && i.exe.is_some())
        );
    }
    #[test]
    fn known_document_overwrites_trigger_bulk_rule() {
        let paths: Vec<_> = (0..60)
            .map(|i| format!("/home/review/Documents/{i}.txt"))
            .collect();
        let baseline = BaselineData::from_pairs(
            paths.iter().map(|p| ("/opt/test-app".into(), p.clone())),
            [],
        );
        let mut engine = AnomalyEngine::with_context(baseline, Allowlist::default());
        let incidents: Vec<_> = paths
            .iter()
            .flat_map(|p| engine.observe(&file(p, FileKind::Write)))
            .collect();
        assert!(
            incidents
                .iter()
                .any(|i| i.details["rule"] == "bulk_mutation")
        );
    }
    #[test]
    fn freshly_created_output_is_not_bulk_mutation() {
        let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let probe = dir.path().join("birth-time-probe");
        std::fs::write(&probe, b"x").unwrap();
        if std::fs::symlink_metadata(&probe)
            .unwrap()
            .created()
            .is_err()
        {
            // The filter intentionally falls back to reporting when birth time
            // is unavailable, so this assertion only applies to supporting
            // filesystems.
            return;
        }
        std::fs::remove_file(&probe).unwrap();
        let mut config = crate::config::RuleConfig {
            bulk_file_threshold: 2,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let mut engine =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), config);
        let mut incidents = Vec::new();
        for index in 0..4 {
            let path = dir.path().join(format!("{index}.json"));
            std::fs::write(&path, b"output").unwrap();
            let mut entry = file(path.to_str().unwrap(), FileKind::Write);
            entry.ts_ms = now_ms();
            incidents.extend(engine.observe(&entry));
        }
        assert!(
            !incidents
                .iter()
                .any(|incident| incident.details["rule"] == "bulk_mutation")
        );
    }

    #[test]
    fn novel_network_destinations_are_learned_after_first_contact() {
        let baseline = BaselineData::from_pairs(
            [],
            [("/opt/test-app".to_string(), "1.1.1.1:443".to_string())],
        );
        let mut config = crate::config::RuleConfig {
            novel_network_min_destinations: 1,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let mut engine = AnomalyEngine::configured(baseline, Allowlist::default(), config);
        let mut first = network();
        first.ts_ms = 1_000_000;
        assert!(
            engine
                .observe(&first)
                .iter()
                .any(|incident| incident.details["rule"] == "novel_network")
        );
        let mut second = network();
        second.ts_ms = 1_000_001;
        assert!(
            !engine
                .observe(&second)
                .iter()
                .any(|incident| incident.details["rule"] == "novel_network")
        );
    }

    #[test]
    fn network_baseline_ignores_optional_hostname_label() {
        let baseline = BaselineData::from_pairs(
            [],
            [(
                "/opt/test-app".to_string(),
                "8.8.8.8:443 (dns.google)".to_string(),
            )],
        );
        let mut config = crate::config::RuleConfig {
            novel_network_min_destinations: 1,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let mut engine = AnomalyEngine::configured(baseline, Allowlist::default(), config);
        assert!(engine.observe(&network()).is_empty());

        let mut resolved = network();
        if let ObservedEvent::Connect(net) = &mut resolved.event {
            net.hostname = Some("dns.google".into());
        }
        let baseline = BaselineData::from_pairs(
            [],
            [("/opt/test-app".to_string(), "8.8.8.8:443".to_string())],
        );
        let mut config = crate::config::RuleConfig {
            novel_network_min_destinations: 1,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let mut engine = AnomalyEngine::configured(baseline, Allowlist::default(), config);
        assert!(engine.observe(&resolved).is_empty());
    }

    #[test]
    fn tailscale_magic_dns_is_not_a_public_destination() {
        let mut entry = network();
        if let ObservedEvent::Connect(net) = &mut entry.event {
            net.addr = [100, 100, 100, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            net.remote_port = 53;
        }
        let ObservedEvent::Connect(net) = &entry.event else {
            unreachable!();
        };
        assert!(!is_public_destination(net));
        assert_eq!(
            crate::net_context::address_scope(net_ip(net).unwrap()),
            "tailscale-magicdns"
        );
    }

    fn with_destination(mut entry: ActivityEntry, addr: [u8; 4], port: u16) -> ActivityEntry {
        if let ObservedEvent::Connect(net) = &mut entry.event {
            net.addr = [
                addr[0], addr[1], addr[2], addr[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            net.remote_port = port;
        }
        entry
    }

    #[test]
    fn high_churn_matches_without_an_allowlist_registration() {
        let engine = AnomalyEngine::new();
        let mut entry = network();
        entry.exe = Some("/usr/bin/transmission-gtk".into());
        if let ObservedEvent::Connect(net) = &mut entry.event {
            net.comm = "transmission-gt".into();
        }
        assert!(engine.high_churn_entry(&entry));
    }

    #[test]
    fn tailscale_magic_dns_is_not_novel_or_egress() {
        let mut engine = AnomalyEngine::new();
        engine.observe(&file("/root/.ssh/key", FileKind::Read));
        let incidents = engine.observe(&with_destination(network(), [100, 100, 100, 100], 53));
        assert!(!incidents.iter().any(|i| matches!(
            i.details["rule"].as_str(),
            Some("novel_network" | "sensitive_egress")
        )));
    }

    #[test]
    fn tailscale_peers_get_a_specific_low_severity_novel_alert() {
        let mut config = crate::config::RuleConfig {
            novel_network_min_destinations: 1,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let baseline = BaselineData::from_pairs(
            [],
            [("/opt/test-app".to_string(), "1.1.1.1:443".to_string())],
        );
        let mut engine = AnomalyEngine::configured(baseline, Allowlist::default(), config);
        let mut entry = with_destination(network(), [100, 100, 100, 101], 443);
        entry.ts_ms = 1_000_000;
        let incidents = engine.observe(&entry);
        let incident = incidents
            .iter()
            .find(|i| i.details["rule"] == "novel_network")
            .unwrap_or_else(|| panic!("tailscale peer should be novel: {incidents:?}"));
        assert_eq!(incident.title, "Novel Tailscale destination");
        assert_eq!(incident.severity, Severity::Low);
        assert_eq!(incident.details["destination_scope"], "tailscale");
        let mut second = entry;
        second.ts_ms = 1_000_001;
        assert!(
            !engine
                .observe(&second)
                .iter()
                .any(|i| i.details["rule"] == "novel_network")
        );
    }

    #[test]
    fn sensitive_egress_to_a_tailscale_peer_keeps_the_scope() {
        let mut engine = AnomalyEngine::new();
        engine.observe(&file("/root/.ssh/key", FileKind::Read));
        let incidents = engine.observe(&with_destination(network(), [100, 100, 100, 101], 443));
        let incident = incidents
            .iter()
            .find(|i| i.details["rule"] == "sensitive_egress")
            .expect("tailscale peer egress should be flagged");
        assert_eq!(incident.details["destination_scope"], "tailscale");
    }

    #[test]
    fn incoming_tailscale_connections_are_scoped_separately() {
        let mut entry = network();
        entry.event = ObservedEvent::Accept(NetEvent {
            pid: 123,
            uid: 1000,
            comm: "test-app".into(),
            family: 2,
            addr: [100, 100, 100, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            local_port: 22,
            remote_port: 45_000,
            hostname: Some("peer.tailnet".into()),
            fd: None,
        });
        let incidents = AnomalyEngine::new().observe(&entry);
        let incident = incidents
            .iter()
            .find(|i| i.details["rule"] == "incoming_connection")
            .expect("tailscale inbound should be reported");
        assert_eq!(incident.details["source_scope"], "tailscale");
        assert_eq!(incident.severity, Severity::Medium);
    }

    #[test]
    fn one_sensitive_path_incident_per_category_and_actor() {
        let mut engine = AnomalyEngine::new();
        let mut incidents =
            engine.observe(&file("/home/alice/.config/gh/config.yml", FileKind::Read));
        incidents.extend(engine.observe(&file("/home/alice/.config/gh/hosts.yml", FileKind::Read)));
        assert_eq!(
            incidents
                .iter()
                .filter(|incident| incident.details["rule"] == "sensitive_path")
                .count(),
            1
        );
        let other = engine.observe(&file("/home/alice/.ssh/id_ed25519", FileKind::Read));
        assert_eq!(
            other
                .iter()
                .filter(|incident| incident.details["rule"] == "sensitive_path")
                .count(),
            1
        );
    }

    #[test]
    fn bulk_scope_separates_project_workloads_from_broad_mutation() {
        let home = Path::new("/home/alice");
        assert_eq!(
            bulk_scope(
                ["/home/alice/project/a.txt", "/home/alice/project/b.txt"],
                Some(home)
            ),
            ("single_directory", Severity::Low)
        );
        assert_eq!(
            bulk_scope(
                ["/home/alice/project-a/a.txt", "/home/alice/project-b/b.txt"],
                Some(home)
            ),
            ("home_root", Severity::High)
        );
        assert_eq!(
            bulk_scope(["/home/alice/a.txt", "/home/alice/b.txt"], Some(home)),
            ("home_root", Severity::High)
        );
        assert_eq!(
            bulk_scope(["/etc/a", "/etc/b"], Some(home)),
            ("system_paths", Severity::High)
        );
        assert_eq!(
            bulk_scope(["/work/a", "/work/b"], Some(home)),
            ("multiple_directories", Severity::Medium)
        );
        assert_eq!(
            bulk_scope(["/var/lib/plex/a", "/var/lib/plex/b"], Some(home)),
            ("single_directory", Severity::Low)
        );
    }

    #[test]
    fn bulk_mutation_severity_tracks_directory_scope() {
        let mut config = crate::config::RuleConfig {
            bulk_file_threshold: 2,
            ..Default::default()
        };
        config.dedup_window_ms = 0;
        let mut project = AnomalyEngine::configured(
            BaselineData::default(),
            Allowlist::default(),
            config.clone(),
        );
        project
            .homes
            .insert("1000".into(), 1_000_000, Some(PathBuf::from("/home/alice")));
        assert!(
            project
                .observe(&file("/home/alice/project/a", FileKind::Write))
                .is_empty()
        );
        let incident = project
            .observe(&file("/home/alice/project/b", FileKind::Write))
            .into_iter()
            .find(|incident| incident.details["rule"] == "bulk_mutation")
            .unwrap();
        assert_eq!(incident.severity, Severity::Low);
        assert_eq!(incident.details["scope"], "single_directory");

        let mut home_root =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), config);
        home_root
            .homes
            .insert("1000".into(), 1_000_000, Some(PathBuf::from("/home/alice")));
        home_root.observe(&file("/home/alice/a", FileKind::Write));
        let incident = home_root
            .observe(&file("/home/alice/b", FileKind::Write))
            .into_iter()
            .find(|incident| incident.details["rule"] == "bulk_mutation")
            .unwrap();
        assert_eq!(incident.severity, Severity::High);
        assert_eq!(incident.details["scope"], "home_root");
    }

    #[test]
    fn credential_access_does_not_cross_process_generations() {
        let mut engine = AnomalyEngine::new();
        engine.observe(&file("/root/.ssh/key", FileKind::Read));
        let mut net = network();
        net.process.as_mut().unwrap().start_ns = 2;
        assert!(
            !engine
                .observe(&net)
                .iter()
                .any(|i| i.details["rule"] == "sensitive_egress")
        );
        // Process traffic summaries do not by themselves create egress events.
        net.event = ObservedEvent::Traffic(TrafficSummary {
            pid: 123,
            comm: "test-app".into(),
            sent: 10,
            recv: 0,
        });
        assert!(engine.observe(&net).is_empty());
    }
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    use electric_eye_core::ExecEvent;
    fn write(pid: u32, ts_ms: u64, path: &str) -> ActivityEntry {
        ActivityEntry {
            executable_identity: None,
            ts_ms,
            event_id: None,
            syscall_result: Some(1),
            process: Some(crate::api::ProcessIdentity {
                boot_id: "boot".into(),
                pid,
                start_ns: pid as u64,
            }),
            path_resolution: Some("kernel".into()),
            process_info: None,
            application: None,
            event: ObservedEvent::FileWrite(electric_eye_core::FileEvent {
                pid,
                uid: 1000,
                comm: "writer".into(),
                path: path.into(),
                kind: FileKind::Write,
                bytes: Some(1),
                count: Some(1),
            }),
            unit: None,
            nix: None,
            parent: None,
            exe: Some("/opt/writer".into()),
        }
    }
    fn read(pid: u32, path: &str) -> ActivityEntry {
        let mut entry = write(pid, 1_000_000, path);
        entry.event = ObservedEvent::FileRead(electric_eye_core::FileEvent {
            pid,
            uid: 1000,
            comm: "reader".into(),
            path: path.into(),
            kind: FileKind::Read,
            bytes: None,
            count: None,
        });
        entry
    }

    #[test]
    fn expired_actors_and_paths_are_pruned_and_busy_windows_are_bounded() {
        let config = crate::config::RuleConfig {
            max_actors: 4,
            max_dedup_entries: 8,
            max_events_per_actor: 2,
            bulk_file_threshold: 2,
            credential_category_threshold: 2,
            sensitive_window_ms: 10,
            bulk_window_ms: 10,
            dedup_window_ms: 10,
            prune_interval_ms: 1,
            ..Default::default()
        };
        let mut engine =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), config);
        for i in 1..10000 {
            engine.observe(&write(i, i as u64, &format!("/home/review/.ssh/key-{i}")));
            assert!(
                engine.sensitive.len() <= 4
                    && engine.mutations.len() <= 4
                    && engine.dedup.len() <= 8
            );
        }
        for i in 10000..10020 {
            engine.observe(&write(10000, i, &format!("/home/review/.ssh/key-{i}")));
        }
        assert!(engine.sensitive.values().all(|w| w.len() <= 2));
        assert!(engine.mutations.values().all(|w| w.len() <= 2));
        engine.prune(11000);
        assert_eq!(
            (
                engine.sensitive.len(),
                engine.mutations.len(),
                engine.dedup.len()
            ),
            (0, 0, 0)
        );
        let mut e = write(10000, 12000, "/home/review/.ssh/key");
        engine.observe(&e);
        e.event = ObservedEvent::Exit(electric_eye_core::ExitEvent {
            pid: 10000,
            uid: 1000,
            comm: "writer".into(),
        });
        engine.observe(&e);
        assert_eq!((engine.sensitive.len(), engine.mutations.len()), (0, 0));
    }
    #[test]
    fn mapped_loopback_private_and_link_local_destinations_are_not_public() {
        for address in [
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:192.168.1.1",
            "::ffff:169.254.1.1",
            "::",
            "ff02::1",
        ] {
            let net = NetEvent {
                pid: 1,
                uid: 1000,
                comm: "test".into(),
                family: 10,
                addr: address.parse::<Ipv6Addr>().unwrap().octets(),
                local_port: 12345,
                remote_port: 443,
                hostname: None,
                fd: None,
            };
            assert!(!is_public_destination(&net), "{address}");
        }
    }
    #[test]
    fn configurable_policy_thresholds_allowlist_and_disable_switches_take_effect() {
        let config: crate::config::Config = toml::from_str(
            r#"
[rules]
builtin_sensitive_paths = false
bulk_file_threshold = 2
credential_sweep = false
[[rules.sensitive_paths]]
prefix = "/work/private"
category = "Project secrets"
severity = "medium"
[[rules.allowlist]]
application = "/opt/allowed"
subject_prefix = "/work/private"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        let allowlist = Allowlist::load(&config.rules);
        let mut engine =
            AnomalyEngine::configured(BaselineData::default(), allowlist, config.rules.clone());
        let incidents = engine.observe(&write(1, 1000, "/work/private/key"));
        assert!(
            incidents
                .iter()
                .any(|i| i.title.ends_with("Project secrets") && i.severity == Severity::Medium)
        );
        let mut e = write(2, 1001, "/work/private/allowed");
        e.exe = Some("/opt/allowed".into());
        e.executable_identity = Some(engine.allowlist.trust_fixture("/opt/allowed"));
        engine
            .allowlist
            .rules
            .push(("/opt/allowed".into(), "/work/private".into()));
        assert!(engine.observe(&e).is_empty());
        assert!(
            engine
                .observe(&write(1, 1002, "/work/second"))
                .iter()
                .any(|i| i.details["rule"] == "bulk_mutation")
        );
        let mut disabled = config.rules;
        disabled.sensitive_path = false;
        disabled.bulk_mutation = false;
        let mut engine =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), disabled);
        assert!(
            engine
                .observe(&write(1, 1000, "/work/private/key"))
                .is_empty()
        );
    }

    #[test]
    fn listing_a_sensitive_directory_is_not_a_credential_read() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(".aws");
        std::fs::create_dir(&dir).unwrap();
        let file_path = dir.join("credentials");
        std::fs::write(&file_path, b"test").unwrap();
        let dir_text = dir.to_string_lossy().into_owned();
        let file_text = file_path.to_string_lossy().into_owned();

        let mut rules = crate::config::RuleConfig {
            builtin_sensitive_paths: false,
            ..Default::default()
        };
        rules.sensitive_paths = vec![crate::config::SensitivePath {
            prefix: dir_text.clone(),
            category: "AWS credentials".into(),
            severity: Severity::High,
        }];
        let mut engine =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), rules);
        assert!(
            engine.observe(&read(1, &dir_text)).is_empty(),
            "directory metadata was treated as a credential read"
        );
        assert!(
            engine
                .observe(&read(2, &file_text))
                .iter()
                .any(|incident| incident.title.contains("AWS credentials")),
            "file access inside the directory was not classified"
        );
    }

    fn identity(pid: u32) -> crate::api::ProcessIdentity {
        crate::api::ProcessIdentity {
            pid,
            start_ns: pid as u64,
            boot_id: "boot".into(),
        }
    }

    fn trusted_ssh_exec(pid: u32, host: &str) -> ActivityEntry {
        let mut entry = write(pid, 1_000_000, "");
        entry.syscall_result = None;
        entry.path_resolution = None;
        entry.parent = Some("git".into());
        entry.exe = Some("/usr/bin/ssh".into());
        entry.executable_identity = Some(crate::provenance::FileIdentity {
            device: 1,
            inode: 2,
        });
        entry.process_info = Some(crate::process::ProcessRecord::synthetic(
            identity(pid),
            1_000_000,
            "ssh",
            &["ssh", &format!("git@{host}"), "git-upload-pack", "repo.git"],
        ));
        entry.event = ObservedEvent::Exec(ExecEvent {
            pid,
            ppid: 1,
            uid: 1000,
            comm: "ssh".into(),
            exe: PathBuf::from("/usr/bin/ssh"),
            start_ticks: pid as u64,
        });
        entry
    }

    fn known_host_ssh_exec(pid: u32, host: &str) -> ActivityEntry {
        let mut entry = trusted_ssh_exec(pid, host);
        entry.parent = None;
        entry.event = ObservedEvent::Exec(ExecEvent {
            pid,
            ppid: 1,
            uid: 1000,
            comm: "ssh".into(),
            exe: PathBuf::from("/usr/bin/ssh"),
            start_ticks: pid as u64,
        });
        entry
    }

    fn ssh_read(pid: u32) -> ActivityEntry {
        let mut entry = read(pid, "/home/alice/.ssh/id_ed25519");
        entry.exe = Some("/usr/bin/ssh".into());
        entry.executable_identity = Some(crate::provenance::FileIdentity {
            device: 1,
            inode: 2,
        });
        entry.parent = Some("git".into());
        if let ObservedEvent::FileRead(event) = &mut entry.event {
            event.comm = "ssh".into();
        }
        entry
    }

    #[test]
    fn parent_process_name_does_not_grant_ssh_trust() {
        let mut engine = AnomalyEngine::new();
        engine.observe(&trusted_ssh_exec(10, "github.com"));
        assert!(
            engine
                .observe(&ssh_read(10))
                .iter()
                .any(|incident| incident.title.contains("SSH"))
        );
    }

    #[test]
    fn known_hosts_is_a_default_allow_for_ssh() {
        let temp = tempfile::tempdir().unwrap();
        let ssh_dir = temp.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::write(
            ssh_dir.join("known_hosts"),
            "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
        )
        .unwrap();
        let mut engine = AnomalyEngine::configured(
            BaselineData::default(),
            Allowlist::default(),
            crate::config::RuleConfig::default(),
        );
        engine
            .homes
            .insert("1000".into(), 1_000_000, Some(temp.path().to_path_buf()));
        engine.allowlist.trust_fixture("/usr/bin/ssh");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !engine
            .known_hosts
            .is_known(Some(temp.path()), "github.com", 22)
        {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let mut exec = known_host_ssh_exec(40, "github.com");
        exec.process_info.as_mut().unwrap().argv = vec!["ssh".into(), "git@github.com".into()];
        assert!(engine.observe(&exec).is_empty());
        assert!(
            engine.observe(&ssh_read(40)).is_empty(),
            "known-host SSH read produced a credential incident"
        );
        assert!(
            engine
                .observe(&known_host_ssh_exec(41, "unknown.example"))
                .is_empty(),
            "exec event itself should not be a credential incident"
        );
        assert!(
            engine
                .observe(&ssh_read(41))
                .iter()
                .any(|incident| incident.title.contains("SSH")),
            "unknown SSH host was suppressed"
        );
    }

    #[test]
    fn spoofed_names_paths_and_inodes_do_not_grant_exemptions() {
        for comm in ["git", "cargo", "tailscaled", "sudo", "ssh", "firefox"] {
            let mut engine =
                AnomalyEngine::with_context(BaselineData::default(), Allowlist::load_default());
            let mut entry = read(70, "/etc/gshadow");
            entry.exe = Some("/tmp/payload".into());
            if let ObservedEvent::FileRead(event) = &mut entry.event {
                event.comm = comm.into();
            }
            assert!(!engine.observe(&entry).is_empty(), "spoofed {comm}");
        }
        for observed in [
            None,
            Some(crate::provenance::FileIdentity {
                device: 1,
                inode: 99,
            }),
        ] {
            let mut engine = AnomalyEngine::new();
            engine.allowlist.trust_fixture("/usr/bin/git");
            engine
                .allowlist
                .rules
                .push(("/usr/bin/git".into(), "*".into()));
            let mut entry = read(71, "/etc/shadow");
            entry.exe = Some("/usr/bin/git".into());
            entry.executable_identity = observed;
            assert!(!engine.observe(&entry).is_empty());
        }
    }

    #[test]
    fn all_supported_credential_families_feed_sensitive_detection() {
        for path in [
            "/etc/gshadow",
            "/etc/sudoers.d/fixture",
            "/home/review/.config/chromium/Default/Login Data",
            "/home/review/.config/BraveSoftware/Brave-Browser/Default/Login Data",
            "/home/review/.local/share/keyrings/login.keyring",
            "/home/review/.git-credentials",
        ] {
            let mut engine = AnomalyEngine::new();
            let incidents = engine.observe(&read(72, path));
            assert!(
                incidents
                    .iter()
                    .any(|incident| incident.details["rule"] == "sensitive_path"),
                "{path}"
            );
        }
    }

    fn incoming_ssh(pid: u32, source: [u8; 4]) -> ActivityEntry {
        let mut entry = write(pid, 1_000_000, "");
        entry.syscall_result = None;
        entry.path_resolution = None;
        entry.exe = Some("/usr/sbin/sshd".into());
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&source);
        entry.event = ObservedEvent::Accept(NetEvent {
            pid,
            uid: 0,
            comm: "sshd".into(),
            family: 2,
            addr,
            local_port: 22,
            remote_port: 55_555,
            hostname: Some("client.example".into()),
            fd: None,
        });
        entry
    }

    #[test]
    fn incoming_connections_are_monitored_and_allowlisted_by_destination() {
        let mut engine = AnomalyEngine::configured(
            BaselineData::default(),
            Allowlist::default(),
            crate::config::RuleConfig::default(),
        );
        let incidents = engine.observe(&incoming_ssh(1, [203, 0, 113, 9]));
        let remote = incidents
            .iter()
            .find(|incident| incident.title.starts_with("Incoming connection: SSH"))
            .unwrap_or_else(|| panic!("{incidents:?}"));
        assert_eq!(remote.severity, Severity::High);
        assert_eq!(remote.details["source_scope"], "remote");

        assert!(
            engine
                .observe(&incoming_ssh(2, [192, 168, 1, 20]))
                .is_empty(),
            "local-network incoming traffic produced an incident by default"
        );
        assert!(
            engine.observe(&incoming_ssh(3, [127, 0, 0, 1])).is_empty(),
            "same-machine incoming traffic produced an incident by default"
        );

        let local_rules = crate::config::RuleConfig {
            incoming_local_connections: true,
            ..Default::default()
        };
        let mut local_engine =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), local_rules);
        let local = local_engine.observe(&incoming_ssh(2, [192, 168, 1, 20]));
        let local = local
            .iter()
            .find(|incident| incident.title.starts_with("Incoming connection: SSH"))
            .unwrap_or_else(|| panic!("{local:?}"));
        assert_eq!(local.severity, Severity::Medium);
        assert_eq!(local.details["source_scope"], "local_network");
        let same = local_engine.observe(&incoming_ssh(3, [127, 0, 0, 1]));
        let same = same
            .iter()
            .find(|incident| incident.title.starts_with("Incoming connection: SSH"))
            .unwrap_or_else(|| panic!("{same:?}"));
        assert_eq!(same.severity, Severity::Medium);
        assert_eq!(same.details["source_scope"], "same_machine");

        let mut high_churn = incoming_ssh(4, [203, 0, 113, 10]);
        high_churn.exe = Some("/usr/bin/transmission-gtk".into());
        high_churn.executable_identity =
            Some(engine.allowlist.trust_fixture("/usr/bin/transmission-gtk"));
        assert!(
            engine.observe(&high_churn).is_empty(),
            "high-churn peer traffic produced incoming incidents"
        );

        let rules = crate::config::RuleConfig {
            network_allowlist: vec![crate::config::NetworkAllowRule {
                application: "sshd".into(),
                destination: "203.0.113.0/24".into(),
                direction: crate::config::NetworkDirection::Inbound,
            }],
            ..Default::default()
        };
        let mut allowed =
            AnomalyEngine::configured(BaselineData::default(), Allowlist::default(), rules);
        let mut incoming = incoming_ssh(2, [203, 0, 113, 9]);
        incoming.executable_identity = Some(allowed.allowlist.trust_fixture("/usr/sbin/sshd"));
        assert!(allowed.observe(&incoming).is_empty());
        assert!(
            !allowed
                .observe(&incoming_ssh(3, [198, 51, 100, 7]))
                .is_empty(),
            "CIDR allowlist was too broad"
        );
    }
}
