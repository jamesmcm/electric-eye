use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// Defaults live next to their types so partial TOML tables inherit individual fields.
macro_rules! settings {
    ($name:ident { $($field:ident: $ty:ty = $value:expr),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
        impl Default for $name {
            fn default() -> Self { Self { $($field: $value),* } }
        }
    };
}
settings!(Config {
    capture_argv: bool = true,
    max_argv_bytes: usize = 512,
    redact_arguments: Vec<String> = strings(&["--password", "--token", "--secret", "--api-key", "--access-token", "--authorization"]),
    ignore_paths: Vec<String> = Vec::new(),
    grouping: Vec<GroupOverride> = Vec::new(),
    focus: Vec<FocusRule> = Vec::new(),
    mcp_tools: Vec<String> = Vec::new(),
    raw_retention_minutes: u64 = 5,
    activity_retention_days: u64 = 30,
    process_retention_days: u64 = 30,
    flow_retention_days: u64 = 30,
    summary_retention_days: u64 = 30,
    noise_retention_days: u64 = 7,
    incident_high_retention_days: u64 = 365,
    incident_medium_retention_days: u64 = 90,
    incident_low_retention_days: u64 = 30,
    rules: RuleConfig = RuleConfig::default(),
    limits: Limits = Limits::default(),
    capture: CaptureConfig = CaptureConfig::default(),
    correlation: CorrelationConfig = CorrelationConfig::default(),
    journal: JournalConfig = JournalConfig::default(),
});
settings!(RuleConfig {
    sensitive_path: bool = true,
    credential_sweep: bool = true,
    bulk_mutation: bool = true,
    suspicious_execution: bool = true,
    sensitive_egress: bool = true,
    novel_network: bool = true,
    builtin_sensitive_paths: bool = true,
    builtin_auth_allowlist: bool = true,
    builtin_noise_allowlist: bool = true,
    known_hosts_allow: bool = true,
    incoming_connections: bool = true,
    incoming_local_connections: bool = false,
    sensitive_window_ms: u64 = 60_000,
    bulk_window_ms: u64 = 10_000,
    dedup_window_ms: u64 = 300_000,
    prune_interval_ms: u64 = 1_000,
    bulk_file_threshold: usize = 50,
    credential_category_threshold: usize = 3,
    novel_network_min_destinations: usize = 5,
    max_actors: usize = 8192,
    max_events_per_actor: usize = 4096,
    max_dedup_entries: usize = 32768,
    max_baseline_entries: usize = 65536,
    sensitive_paths: Vec<SensitivePath> = Vec::new(),
    allowlist: Vec<AllowRule> = Vec::new(),
    network_allowlist: Vec<NetworkAllowRule> = Vec::new(),
    browser_prefixes: Vec<String> = strings(&["/usr/lib/firefox", "/usr/bin/firefox", "/opt/firefox", "/usr/lib/chromium", "/usr/bin/chromium", "/opt/google/chrome", "/opt/brave", "/usr/bin/brave", "/usr/lib/brave"]),
    browser_nix_names: Vec<String> = strings(&["-firefox", "-chromium", "-google-chrome", "-brave"]),
    high_churn_apps: Vec<String> = strings(&["transmission", "qbittorrent", "deluge", "ktorrent", "aria2", "rtorrent", "thunar", "tumblerd", "tracker", "baloo", "cargo", "rustc", "nix-daemon", "nix-store", "node", "bun", "deno", "opencode", "tailscaled", "Plex Media Server"]),
    bulk_noise_paths: Vec<String> = strings(&["/.cache/", "/.thumbnails/", "/cache/", "/target/", "/node_modules/", "/.mozilla/", "/.config/chromium/", "/.config/google-chrome/", "/.local/share/trash/", "/tmp/", "/var/tmp/", "/var/cache/"]),
    suspicious_prefixes: Vec<String> = strings(&["/tmp/", "/dev/shm/", "/run/user/"]),
    suspicious_home_paths: Vec<String> = strings(&["Downloads", ".cache", ".local/share/Trash"]),
});
settings!(Limits {
    aggregation_ms: u64 = 5000,
    write_top: usize = 32,
    traffic_top: usize = 8,
    window_entries: usize = 4096,
    activity_entries: usize = 2048,
    app_entries: usize = 4096,
    process_entries: usize = 8192,
    retired_process_entries: usize = 32768,
    document_entries: usize = 2048,
    application_entries: usize = 4096,
    application_members: usize = 4096,
    flow_entries: usize = 32768,
    flow_contributors: usize = 1024,
    summary_entries: usize = 4096,
    summary_files: usize = 4096,
    summary_evidence: usize = 64,
    correlation_writes: usize = 8192,
    correlation_processes: usize = 32768,
    summary_flush_entries: usize = 512,
    incident_entries: usize = 200,
    dns_entries: usize = 4096,
    dns_pending: usize = 256,
    dns_ttl_ms: u64 = 300000,
    api_workers: usize = 4,
    api_queue: usize = 1,
    api_accept_batch: usize = 16,
    api_poll_ms: u64 = 10,
    api_request_bytes: usize = 16384,
    api_timeout_ms: u64 = 500,
    api_query_rows: usize = 1000,
    api_process_rows: usize = 10000,
    store_queue: usize = 8192,
    store_batch: usize = 128,
    store_flush_ms: u64 = 200,
    store_maintenance_ms: u64 = 60000,
    activity_bucket_ms: i64 = 300000,
    collector_batch: usize = 4096,
    idle_sleep_ms: u64 = 20,
});
settings!(CaptureConfig {
    ring_bytes: u32 = 1 << 24,
    pending_entries: u32 = 8192,
    socket_entries: u32 = 32768,
    network_pending_entries: u32 = 8192,
    read_prefix_entries: u32 = 4096,
    builtin_read_prefixes: bool = true,
    read_prefixes: Vec<String> = Vec::new(),
    noise_paths: Vec<String> = strings(&["/dev/", "/proc/", "/sys/", "/run/"]),
});
settings!(CorrelationConfig {
    build_session: bool = true,
    application_start: bool = true,
    save_sequence: bool = true,
    download_like: bool = true,
    save_window_ms: u64 = 10000,
    download_window_ms: u64 = 30000,
    compiler_names: Vec<String> = strings(&["rustc", "gcc", "g++", "cc", "c++", "clang", "clang++", "make", "ninja"]),
    build_driver_names: Vec<String> = strings(&["cargo", "go"]),
    build_subcommands: Vec<String> = strings(&["build", "check", "test", "run", "clippy", "bench", "install"]),
    cross_compiler_patterns: bool = true,
});
settings!(JournalConfig {
    enabled: bool = true,
    queue_entries: usize = 128,
    context_window_secs: u64 = 60,
    context_lines: usize = 20,
    timeout_ms: u64 = 200,
    max_output_bytes: usize = 131072,
    max_line_chars: usize = 500,
});
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupOverride {
    pub executable: String,
    pub application: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FocusRule {
    pub name: String,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub log_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub application: String,
    pub subject_prefix: String,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection {
    Outbound,
    Inbound,
    #[default]
    Both,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAllowRule {
    /// Protected executable path, installed executable name, or "*".
    pub application: String,
    /// Hostname suffix, exact IP, or CIDR (for example "github.com" or
    /// "192.168.0.0/16").
    pub destination: String,
    #[serde(default)]
    pub direction: NetworkDirection,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePath {
    pub prefix: String,
    pub category: String,
    pub severity: crate::rules::Severity,
}
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}

impl Config {
    pub fn discover(explicit: Option<PathBuf>) -> Option<PathBuf> {
        Self::discover_in(
            explicit,
            std::env::var_os("ELECTRIC_EYE_CONFIG").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
            Path::new("/etc/electric-eye/config.toml"),
        )
    }
    fn discover_in(
        explicit: Option<PathBuf>,
        env: Option<PathBuf>,
        home: Option<PathBuf>,
        system: &Path,
    ) -> Option<PathBuf> {
        explicit
            .or(env)
            .or_else(|| {
                home.and_then(|home| {
                    let preferred = home.join(".config/electric-eye/config.toml");
                    if preferred.exists() {
                        return Some(preferred);
                    }
                    let legacy = home.join(".config/electriceye/config.toml");
                    legacy.exists().then_some(legacy)
                })
            })
            .or_else(|| system.exists().then(|| system.to_path_buf()))
    }
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use anyhow::Context;
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("parsing TOML {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_argv_bytes <= 512,
            "max_argv_bytes must be <=512 (kernel ABI ceiling)"
        );
        anyhow::ensure!(
            (1..=1440).contains(&self.raw_retention_minutes),
            "raw_retention_minutes must be 1..1440"
        );
        anyhow::ensure!(
            [
                self.activity_retention_days,
                self.process_retention_days,
                self.flow_retention_days,
                self.summary_retention_days,
                self.noise_retention_days,
                self.incident_high_retention_days,
                self.incident_medium_retention_days,
                self.incident_low_retention_days,
            ]
            .iter()
            .all(|days| (1..=3650).contains(days)),
            "retention days must be 1..3650"
        );
        // Bound allocation sizes and deadline arithmetic before starting any workers.
        for (section, value) in [
            ("limits", serde_json::to_value(&self.limits)?),
            ("rules", serde_json::to_value(&self.rules)?),
            ("journal", serde_json::to_value(&self.journal)?),
            ("correlation", serde_json::to_value(&self.correlation)?),
        ] {
            for (key, value) in value.as_object().unwrap() {
                if let Some(n) = value.as_i64() {
                    let min = if matches!(
                        key.as_str(),
                        "write_top" | "traffic_top" | "novel_network_min_destinations"
                    ) {
                        0
                    } else {
                        1
                    };
                    anyhow::ensure!(
                        (min..=86_400_000).contains(&n),
                        "{section}.{key} must be {min}..86400000"
                    );
                }
            }
        }
        anyhow::ensure!(
            self.limits.api_workers <= 64 && self.limits.dns_pending <= 256,
            "api_workers must be <=64 and dns_pending <=256"
        );
        anyhow::ensure!(
            self.limits.summary_flush_entries <= self.limits.summary_entries,
            "summary_flush_entries must be <=summary_entries"
        );
        anyhow::ensure!(
            self.rules.max_events_per_actor
                >= self
                    .rules
                    .bulk_file_threshold
                    .max(self.rules.credential_category_threshold),
            "max_events_per_actor must cover rule thresholds"
        );
        let c = &self.capture;
        anyhow::ensure!(
            c.ring_bytes.is_power_of_two() && (4096..=1 << 30).contains(&c.ring_bytes),
            "capture.ring_bytes must be a power of two in 4096..1073741824"
        );
        for n in [
            c.pending_entries,
            c.socket_entries,
            c.network_pending_entries,
            c.read_prefix_entries,
        ] {
            anyhow::ensure!(
                (1..=1_048_576).contains(&n),
                "capture map entries must be 1..1048576"
            );
        }
        anyhow::ensure!(
            self.ignore_paths
                .iter()
                .chain(&c.noise_paths)
                .all(|p| p.starts_with('/')),
            "ignored/noise paths must be absolute"
        );
        anyhow::ensure!(
            c.read_prefixes
                .iter()
                .all(|p| p.starts_with('/') && p.len() <= 128),
            "read_prefixes must be absolute and <=128 bytes (kernel ABI ceiling)"
        );
        anyhow::ensure!(
            self.grouping
                .iter()
                .all(|g| g.executable.starts_with('/') && !g.application.is_empty()),
            "grouping overrides require an absolute executable and application name"
        );
        anyhow::ensure!(
            self.rules
                .sensitive_paths
                .iter()
                .all(|p| p.prefix.starts_with('/')
                    && p.prefix.len() <= 128
                    && !p.category.is_empty()),
            "sensitive_paths require absolute prefixes <=128 bytes and category names"
        );
        anyhow::ensure!(
            self.rules
                .allowlist
                .iter()
                .all(|r| !r.application.is_empty() && !r.subject_prefix.is_empty()),
            "allowlist entries must not be empty"
        );
        anyhow::ensure!(
            self.rules
                .network_allowlist
                .iter()
                .all(|r| !r.application.is_empty() && !r.destination.is_empty()),
            "network_allowlist entries must not be empty"
        );
        anyhow::ensure!(
            self.rules
                .suspicious_prefixes
                .iter()
                .all(|p| p.starts_with('/'))
                && self
                    .rules
                    .suspicious_home_paths
                    .iter()
                    .all(|p| !Path::new(p).is_absolute() && !p.split('/').any(|s| s == "..")),
            "suspicious paths must be absolute prefixes or home-relative paths without '..'"
        );
        Ok(())
    }
    pub fn argv(&self, raw: &[u8]) -> (Vec<String>, bool) {
        if !self.capture_argv {
            return (Vec::new(), false);
        }
        let limit = self.max_argv_bytes.min(raw.len());
        let truncated = raw.len() > limit || limit > 0 && raw[..limit].last() != Some(&0);
        let raw = &raw[..limit];
        let mut args: Vec<String> = if raw.is_empty() {
            Vec::new()
        } else {
            raw.split(|b| *b == 0)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect()
        };
        if raw.last() == Some(&0) {
            args.pop();
        }
        let mut next = false;
        for arg in &mut args {
            if next {
                *arg = "[redacted]".into();
                next = false;
                continue;
            }
            let key = arg.split('=').next().unwrap_or_default();
            if self
                .redact_arguments
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case(key))
            {
                if arg.contains('=') {
                    *arg = format!("{key}=[redacted]");
                } else {
                    next = true;
                }
            }
        }
        (args, truncated)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_redaction_preserves_empty_arguments() {
        let mut c = Config::default();
        let (a, t) = c.argv(b"tool\0\0--password=secret\0--token\0value\0");
        assert_eq!(
            a,
            vec!["tool", "", "--password=[redacted]", "--token", "[redacted]"]
        );
        assert!(!t);
        c.max_argv_bytes = 3;
        assert!(c.argv(b"tool\0").1);
        c.capture_argv = false;
        assert!(c.argv(b"secret\0").0.is_empty());
    }
    #[test]
    fn toml_defaults_overrides_and_validation() {
        let default = Config::default();
        default.validate().unwrap();
        let text = toml::to_string_pretty(&default).unwrap();
        let roundtrip: Config = toml::from_str(&text).unwrap();
        roundtrip.validate().unwrap();
        let c: Config = toml::from_str(
            "[rules]\nbulk_file_threshold=2\nsensitive_egress=false\n[limits]\nflow_entries=4",
        )
        .unwrap();
        assert_eq!(c.rules.bulk_file_threshold, 2);
        assert!(!c.rules.sensitive_egress);
        assert_eq!(c.limits.flow_entries, 4);
        assert_eq!(c.limits.api_workers, 4);
        assert!(toml::from_str::<Config>("[rules]\nunknown=true").is_err());
        let mut c = default;
        c.limits.api_workers = 0;
        assert!(c.validate().is_err());
        c.limits.api_workers = 4;
        c.incident_high_retention_days = 0;
        assert!(c.validate().is_err());
        c.incident_high_retention_days = 365;
        c.noise_retention_days = 4000;
        assert!(c.validate().is_err());
        c.noise_retention_days = 7;
        c.rules.max_events_per_actor = 1;
        assert!(c.validate().is_err());
    }
    #[test]
    fn user_configuration_precedes_system_but_explicit_paths_are_required() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let preferred = home.join(".config/electric-eye/config.toml");
        let legacy = home.join(".config/electriceye/config.toml");
        std::fs::create_dir_all(preferred.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "").unwrap();
        let system = home.join("system.toml");
        std::fs::write(&system, "").unwrap();
        // Legacy files keep working, but the new path wins when both exist.
        assert_eq!(
            Config::discover_in(None, None, Some(home.into()), &system),
            Some(legacy)
        );
        std::fs::write(&preferred, "").unwrap();
        assert_eq!(
            Config::discover_in(None, None, Some(home.into()), &system),
            Some(preferred)
        );
        let explicit = home.join("missing.toml");
        assert_eq!(
            Config::discover_in(Some(explicit.clone()), None, Some(home.into()), &system),
            Some(explicit.clone())
        );
        assert!(Config::load(&explicit).is_err());
    }

    #[test]
    fn shipped_toml_lists_every_default_setting() {
        let source = include_str!("../../../config/default.toml");
        let shipped: toml::Value = toml::from_str(source).unwrap();
        let generated: toml::Value =
            toml::from_str(&toml::to_string_pretty(&Config::default()).unwrap()).unwrap();
        assert_eq!(shipped, generated);
        toml::from_str::<Config>(source)
            .unwrap()
            .validate()
            .unwrap();
    }
}
