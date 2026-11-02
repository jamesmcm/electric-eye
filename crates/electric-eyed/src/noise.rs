//! Read-only noise-candidate analysis for `electric-eye noise`.
//!
//! The goal is to suggest likely capture filters and rule allowlists, not to
//! change configuration. Everything is derived from the same recent activity
//! and incident data the query API already exposes.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::api::SharedState;
use crate::config::Config;
use crate::store::StoreClient;

const MIN_PATH_EVENTS: u64 = 50;
const MIN_APP_INCIDENTS: u64 = 10;

#[derive(Default)]
struct PathStat {
    events: u64,
    bytes: u64,
    files: BTreeSet<String>,
    kinds: BTreeSet<String>,
}

fn candidate_prefix(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    for marker in [
        "/.cache/",
        "/target/",
        "/node_modules/",
        "/.hermes/",
        "/workload_runs/",
        "/logs/",
        "/.local/share/opencode/",
        "/var/lib/tailscale/",
    ] {
        if let Some(index) = lower.find(marker) {
            return Some(path[..index + marker.len() - 1].to_string());
        }
    }
    let parent = Path::new(path).parent()?.to_string_lossy().into_owned();
    if matches!(parent.as_str(), "/" | "/tmp" | "/var/tmp" | "/home")
        || parent.starts_with("/tmp/")
        || parent.starts_with("/var/tmp/")
        || parent.starts_with("/home/") && parent.matches('/').count() <= 2
    {
        None
    } else {
        Some(parent)
    }
}

fn sensitive_candidate(path: &str) -> bool {
    [
        "/.ssh",
        "/.gnupg",
        "/.aws",
        "/.azure",
        "/.kube",
        "/.config/gh",
        "/.password-store",
        "/.codex",
        "/.config/opencode",
        "/.local/share/opencode",
        "/.cache",
        "/.hermes",
        "/.mozilla",
        "/.config/chromium",
        "/.config/google-chrome",
        "/etc/",
        "/root/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn already_filtered(path: &str, config: &Config) -> bool {
    if crate::auto_noise::looks_generated(path) {
        return true;
    }
    config
        .ignore_paths
        .iter()
        .chain(config.capture.noise_paths.iter())
        .any(|prefix| path == prefix || path.starts_with(prefix) || prefix.starts_with(path))
}

fn app_already_allowlisted(app: &str, config: &Config) -> bool {
    (config.rules.builtin_noise_allowlist && matches!(app, "tailscaled" | "thunar"))
        || config
            .rules
            .allowlist
            .iter()
            .any(|rule| rule.subject_prefix == "*" && rule.application == app)
}

/// Interpreters, shells and coreutils are process hosts, not applications.
/// Allowlisting them would suppress activity from every script or command the
/// user runs, so they must never become allowlist suggestions.
fn generic_application(app: &str) -> bool {
    let base = app.rsplit('/').next().unwrap_or(app);
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "python"
            | "python3"
            | "node"
            | "nodejs"
            | "bun"
            | "deno"
            | "ruby"
            | "perl"
            | "php"
            | "java"
            | "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "nu"
            | "env"
            | "sudo"
            | "doas"
            | "timeout"
            | "xargs"
            | "find"
            | "make"
            | "cmake"
            | "ninja"
            | "cargo"
            | "git"
            | "cp"
            | "mv"
            | "rm"
            | "cat"
            | "sed"
            | "awk"
            | "grep"
            | "rg"
            | "jq"
            | "tar"
            | "bsdtar"
            | "curl"
            | "wget"
            | "ssh"
            | "scp"
    )
}

fn add_path(stats: &mut HashMap<String, PathStat>, path: &str, kind: &str, count: u64, bytes: u64) {
    let Some(prefix) = candidate_prefix(path) else {
        return;
    };
    let stat = stats.entry(prefix).or_default();
    stat.events = stat.events.saturating_add(count);
    stat.bytes = stat.bytes.saturating_add(bytes);
    stat.files.insert(path.to_string());
    stat.kinds.insert(kind.to_string());
}

fn activity_rows(
    store: Option<&StoreClient>,
    state: &Arc<Mutex<SharedState>>,
    limit: usize,
) -> Vec<Value> {
    if let Some(store) = store
        && let Ok(value) = store.recent_activities(limit)
        && let Some(rows) = value["activities"].as_array()
        && !rows.is_empty()
    {
        return rows.clone();
    }
    let value = state.lock().unwrap().activity_value(limit);
    value["activity"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|entry| {
                    let event = &entry["event"];
                    let kind = match event["event"].as_str()? {
                        "file_open" => "file.open",
                        "file_read" => "file.read",
                        "file_write" => "file.write",
                        "file_unlink" => "file.unlink",
                        "file_rename" => "file.rename",
                        _ => return None,
                    };
                    let subject = event["path"]
                        .as_str()
                        .or_else(|| event["from_path"].as_str())
                        .or_else(|| event["to_path"].as_str())
                        .unwrap_or_default();
                    Some(json!({
                        "kind": kind,
                        "subject": subject,
                        "count": 1,
                        "bytes": event["bytes"].as_u64().unwrap_or(0),
                        "app_name": event["comm"],
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn incidents(
    store: Option<&StoreClient>,
    state: &Arc<Mutex<SharedState>>,
    limit: usize,
) -> Vec<Value> {
    if let Some(store) = store
        && let Ok(value) = store.incidents(limit)
        && let Some(rows) = value["incidents"].as_array()
    {
        return rows.clone();
    }
    state.lock().unwrap().recent_incidents(limit)
}

fn summaries(
    store: Option<&StoreClient>,
    state: &Arc<Mutex<SharedState>>,
    limit: usize,
) -> Vec<Value> {
    if let Some(store) = store
        && let Ok(rows) = store.documents("summaries", limit)
        && !rows.is_empty()
    {
        return rows;
    }
    state.lock().unwrap().documents("summaries", limit)
}

pub fn value(store: Option<&StoreClient>, state: &Arc<Mutex<SharedState>>, limit: usize) -> Value {
    let limit = limit.clamp(1, 1000);
    let config = state.lock().unwrap().config_snapshot();
    let rows = activity_rows(store, state, limit);
    let mut paths: HashMap<String, PathStat> = HashMap::new();
    for row in &rows {
        let kind = row["kind"].as_str().unwrap_or_default();
        if !kind.starts_with("file.") {
            continue;
        }
        let subject = row["subject"].as_str().unwrap_or_default();
        if subject.is_empty() || sensitive_candidate(subject) {
            continue;
        }
        add_path(
            &mut paths,
            subject,
            kind,
            row["count"].as_u64().unwrap_or(1),
            row["bytes"].as_u64().unwrap_or(0),
        );
    }
    let mut path_candidates: Vec<_> = paths
        .into_iter()
        .filter(|(prefix, stat)| {
            stat.events >= MIN_PATH_EVENTS && !already_filtered(prefix, &config)
        })
        .collect();
    path_candidates.sort_by_key(|(_, stat)| std::cmp::Reverse(stat.events));
    path_candidates.truncate(10);

    let mut app_counts: HashMap<String, (u64, HashMap<String, u64>)> = HashMap::new();
    for incident in incidents(store, state, limit) {
        let app = incident["comm"].as_str().unwrap_or_default();
        if app.is_empty() || generic_application(app) || app_already_allowlisted(app, &config) {
            continue;
        }
        let entry = app_counts.entry(app.to_string()).or_default();
        entry.0 += 1;
        *entry
            .1
            .entry(incident["title"].as_str().unwrap_or("unknown").to_string())
            .or_default() += 1;
    }
    let mut app_candidates: Vec<_> = app_counts
        .into_iter()
        .filter(|(_, (count, _))| *count >= MIN_APP_INCIDENTS)
        .collect();
    app_candidates.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
    app_candidates.truncate(10);

    let summary_rows = summaries(store, state, limit);
    let download_like = summary_rows
        .iter()
        .filter(|summary| summary["kind"] == "download_like")
        .count();

    let mut candidates = Vec::new();
    let mut ignore_paths = Vec::new();
    for (prefix, stat) in &path_candidates {
        ignore_paths.push(prefix.clone());
        candidates.push(json!({
            "kind": "path",
            "value": prefix,
            "events": stat.events,
            "bytes": stat.bytes,
            "files": stat.files.len(),
            "activity_kinds": stat.kinds,
            "reason": "file activity concentrated under this prefix",
            "suggested": "ignore_paths"
        }));
    }
    let mut allowlist_apps = Vec::new();
    for (app, (count, rules)) in &app_candidates {
        allowlist_apps.push(app.clone());
        let top: Vec<_> = rules
            .iter()
            .map(|(rule, count)| json!({"title": rule, "count": count}))
            .collect();
        candidates.push(json!({
            "kind": "application",
            "value": app,
            "incidents": count,
            "top_rules": top,
            "reason": "repeated incidents from this identity",
            "suggested": "review",
            "warning": "A wildcard rules.allowlist is broad and does not suppress bulk-mutation incidents."
        }));
    }
    if download_like > 0 {
        candidates.push(json!({
            "kind": "correlation",
            "value": "download_like",
            "summaries": download_like,
            "reason": "network-then-write summaries are often logs, caches, or databases",
            "suggested": "correlation.download_like = false"
        }));
    }

    let mut snippet = String::new();
    if !ignore_paths.is_empty() {
        snippet.push_str(
            "# Review before applying: these prefixes stop matching file events.\nignore_paths = [\n",
        );
        for path in &ignore_paths {
            snippet.push_str(&format!(
                "  {},\n",
                serde_json::to_string(path).unwrap_or_default()
            ));
        }
        snippet.push_str("]\n");
    }
    if !allowlist_apps.is_empty() {
        snippet.push_str(
            "\n# Review candidates only: a wildcard allowlist suppresses every\n\
             # detection rule for the identity and does not suppress bulk-mutation\n\
             # incidents. Uncomment only when the identity is genuinely trusted.\n",
        );
    }
    for app in &allowlist_apps {
        snippet.push_str(&format!(
            "\n# [[rules.allowlist]]\n# application = {}\n# subject_prefix = \"*\"\n",
            serde_json::to_string(app).unwrap_or_default()
        ));
    }
    if download_like > 0 {
        snippet.push_str("\n[correlation]\ndownload_like = false\n");
    }
    if snippet.is_empty() {
        snippet.push_str("# No obvious noise candidates in the current window.\n");
    }

    json!({
        "window": {
            "activity_rows": rows.len(),
            "incidents": incidents(store, state, limit).len(),
            "summaries": summary_rows.len()
        },
        "candidates": candidates,
        "suggested_config": snippet,
        "history": if store.is_some() { "persisted and recent" } else { "recent in-memory observations; persistence disabled" }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::default()
    }

    fn empty_state() -> Arc<Mutex<SharedState>> {
        Arc::new(Mutex::new(SharedState::new()))
    }

    #[test]
    fn detects_high_churn_prefixes_but_not_sensitive_or_existing_filters() {
        assert_eq!(
            candidate_prefix("/home/alice/workload_runs/run-1/out.json").as_deref(),
            Some("/home/alice/workload_runs")
        );
        assert_eq!(
            candidate_prefix("/home/alice/project/target/debug/out").as_deref(),
            Some("/home/alice/project/target")
        );
        assert!(sensitive_candidate("/home/alice/.ssh/id_ed25519"));
        assert!(sensitive_candidate("/home/alice/.cache/tool/state"));
        assert!(!sensitive_candidate("/home/alice/project/out"));
        assert!(already_filtered("/dev/shm/x", &Config::default()));
        assert_eq!(candidate_prefix("/tmp/.tmpABC/file"), None);
    }

    #[test]
    fn path_candidates_are_counted_and_suggest_ignore_paths() {
        let mut stats = HashMap::new();
        add_path(
            &mut stats,
            "/home/alice/workload_runs/run-1/out.json",
            "file.write",
            12,
            4096,
        );
        add_path(
            &mut stats,
            "/home/alice/workload_runs/run-2/out.json",
            "file.write",
            8,
            2048,
        );
        let stat = stats.get("/home/alice/workload_runs").unwrap();
        assert_eq!(stat.events, 20);
        assert_eq!(stat.bytes, 6144);
        assert_eq!(stat.files.len(), 2);

        let state = empty_state();
        let value = value(None, &state, 100);
        assert!(value["candidates"].is_array());
        assert!(value["suggested_config"].is_string());
    }

    #[test]
    fn generic_process_hosts_are_not_allowlist_candidates() {
        for app in ["python3", "python3.14", "node", "bash", "cp", "rm", "curl"] {
            assert!(generic_application(app), "{app}");
        }
        for app in ["gh", "spotify", "freeorionca", "opencode"] {
            assert!(!generic_application(app), "{app}");
        }
    }

    #[test]
    fn auto_noise_paths_are_not_suggested_again() {
        assert!(already_filtered(
            "/home/alice/project/target/debug/out",
            &Config::default()
        ));
        assert!(already_filtered(
            "/home/alice/dom6bot_runs/win-1/out.json",
            &Config::default()
        ));
    }

    #[test]
    fn allowlist_helpers_respect_builtin_and_explicit_entries() {
        let mut config = config();
        assert!(app_already_allowlisted("tailscaled", &config));
        assert!(app_already_allowlisted("thunar", &config));
        assert!(!app_already_allowlisted("hermes", &config));
        config.rules.allowlist.push(crate::config::AllowRule {
            application: "hermes".into(),
            subject_prefix: "*".into(),
        });
        assert!(app_already_allowlisted("hermes", &config));
    }
}
