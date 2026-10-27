//! Bounded incident evidence bundles for user-provided agent harnesses.
//!
//! Electric-eye does not call a model. It renders a prompt and a structured
//! bundle that an MCP client or CLI user can hand to their own harness.

use crate::config::{Config, FocusRule};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn bundle(incident: &Value, config: &Config, home: Option<&Path>) -> Value {
    let actor = &incident["details"]["actor"];
    let app = actor["application"]["name"].as_str().unwrap_or_default();
    let comm = actor["comm"].as_str().unwrap_or_default();
    let executable = actor["executable"].as_str().unwrap_or_default();
    let cwd = actor["cwd"].as_str();
    let paths = incident_paths(incident, actor);
    let focus = config
        .focus
        .iter()
        .find(|rule| focus_matches(rule, app, comm, executable, &paths, home));
    let log_paths = focus
        .map(|rule| {
            if rule.log_paths.is_empty() {
                detected_log_paths(app, comm, executable, cwd, home)
            } else {
                expand_paths(&rule.log_paths, home)
            }
        })
        .unwrap_or_else(|| detected_log_paths(app, comm, executable, cwd, home));
    let harness_logs = describe_files(&log_paths);
    let mut bundle = json!({
        "generated_ms": now_ms(),
        "incident": incident,
        "focus": focus.map(|rule| json!({
            "name": rule.name,
            "applications": rule.applications,
            "paths": rule.paths,
            "configured_log_paths": rule.log_paths,
        })),
        "harness_logs": harness_logs,
        "caveats": [
            "Roles are heuristics; DHT, tracker and BitTorrent payloads are not inspected.",
            "HTTPS payloads are not intercepted; network evidence is metadata, not content.",
            "Incident retention keeps embedded actor/journal/file evidence even after raw events expire.",
            "Harness log paths are detected, not parsed automatically; inspect only the relevant files."
        ]
    });
    let prompt = render_prompt(&bundle);
    bundle["prompt"] = Value::String(prompt);
    bundle
}

fn incident_paths(incident: &Value, actor: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(path) = incident["path"].as_str() {
        paths.push(path.to_string());
    }
    if let Some(files) = incident["details"]["files"].as_array() {
        paths.extend(
            files
                .iter()
                .filter_map(|file| file.as_str())
                .map(str::to_string),
        );
    }
    if let Some(cwd) = actor["cwd"].as_str() {
        paths.push(cwd.to_string());
    }
    paths
}

pub(crate) fn focus_matches(
    rule: &FocusRule,
    app: &str,
    comm: &str,
    executable: &str,
    paths: &[String],
    home: Option<&Path>,
) -> bool {
    let application_match = rule.applications.is_empty()
        || rule.applications.iter().any(|candidate| {
            let candidate = candidate.to_ascii_lowercase();
            app.to_ascii_lowercase().contains(&candidate)
                || comm.to_ascii_lowercase().contains(&candidate)
                || executable.to_ascii_lowercase().contains(&candidate)
        });
    let path_match = rule.paths.is_empty()
        || paths.iter().any(|path| {
            rule.paths.iter().any(|prefix| {
                path.starts_with(expand_home(prefix, home).to_string_lossy().as_ref())
            })
        });
    application_match && path_match
}

pub(crate) fn detected_log_paths(
    app: &str,
    comm: &str,
    executable: &str,
    cwd: Option<&str>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    let Some(home) = home else {
        return Vec::new();
    };
    let mut roots = Vec::new();
    let name = format!("{app} {comm} {executable}").to_ascii_lowercase();
    let mut keys: Vec<String> = Vec::new();
    for known in [
        "codex", "opencode", "hermes", "omarchy", "omp", "claude", "cursor", "aider", "goose",
        "pi", "gemini",
    ] {
        if name.contains(known) {
            keys.push(known.to_string());
            keys.push(format!(".{known}"));
        }
    }
    for value in [app, comm, executable.rsplit('/').next().unwrap_or_default()] {
        let value = value.trim().trim_start_matches('.').to_ascii_lowercase();
        if value.len() >= 2
            && value.len() <= 32
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !keys.iter().any(|key| key.trim_start_matches('.') == value)
        {
            keys.push(value.clone());
            keys.push(format!(".{value}"));
        }
    }
    keys.sort();
    keys.dedup();
    for key in &keys {
        roots.push(home.join(".config").join(key));
        roots.push(home.join(".local/share").join(key));
        roots.push(home.join(".local/state").join(key));
        if key.starts_with('.') {
            roots.push(home.join(key));
        }
    }
    if let Some(cwd) = cwd {
        let cwd = Path::new(cwd);
        for key in &keys {
            roots.push(cwd.join(key).join("logs"));
            roots.push(cwd.join(key).join("sessions"));
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

pub(crate) fn expand_paths(values: &[String], home: Option<&Path>) -> Vec<PathBuf> {
    values
        .iter()
        .map(|value| expand_home(value, home))
        .collect()
}

fn expand_home(value: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/")
        && let Some(home) = home
    {
        return home.join(rest);
    }
    PathBuf::from(value)
}

pub(crate) fn describe_files(paths: &[PathBuf]) -> Vec<Value> {
    let mut files = Vec::new();
    for path in paths {
        collect_files(path, 0, &mut files);
    }
    files.sort_by_key(|file| std::cmp::Reverse(file["modified_ms"].as_u64().unwrap_or(0)));
    files.truncate(20);
    files
}

fn collect_files(path: &Path, depth: usize, out: &mut Vec<Value>) {
    if depth > 3 || out.len() >= 100 {
        return;
    }
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_file() {
        out.push(json!({
            "path": path.display().to_string(),
            "size": metadata.len(),
            "modified_ms": metadata.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok()).map(|duration| duration.as_millis() as u64).unwrap_or(0),
        }));
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_files(&entry.path(), depth + 1, out);
    }
}

fn render_prompt(bundle: &Value) -> String {
    let incident = &bundle["incident"];
    let mut prompt = String::new();
    prompt.push_str("# Electric Eye incident investigation\n\n");
    prompt.push_str(
        "Investigate the incident below using only the supplied evidence. \
Do not claim file contents, HTTPS payloads, intent, or successful completion unless the evidence supports it. \
The monitor is read-only and does not intercept TLS.\n\n",
    );
    prompt.push_str(&format!(
        "Incident: {} [{}]\nApplication: {}\nPID: {}\nTime: {}\n\n",
        incident["title"].as_str().unwrap_or("unknown"),
        incident["severity"].as_str().unwrap_or("unknown"),
        incident["details"]["actor"]["application"]["name"]
            .as_str()
            .or_else(|| incident["comm"].as_str())
            .unwrap_or("unknown"),
        incident["pid"],
        incident["ts_ms"],
    ));
    if let Some(trust) = incident["details"]["package_trust"].as_object() {
        prompt.push_str("## Binary trust\n\n");
        prompt.push_str(&format!(
            "status={} source={} validation={} hash_match={}\n\n",
            trust
                .get("status")
                .map(string)
                .unwrap_or_else(|| "?".into()),
            trust
                .get("source")
                .map(string)
                .unwrap_or_else(|| "?".into()),
            trust
                .get("validation")
                .map(string)
                .unwrap_or_else(|| "?".into()),
            trust
                .get("hash_match")
                .map(string)
                .unwrap_or_else(|| "?".into()),
        ));
    }
    if let Some(focus) = bundle["focus"].as_object() {
        prompt.push_str(&format!(
            "Focused session: {}\n\n",
            focus
                .get("name")
                .map(string)
                .unwrap_or_else(|| "unnamed".into())
        ));
    }
    let logs = bundle["harness_logs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !logs.is_empty() {
        prompt.push_str("## Harness logs detected\n\n");
        prompt.push_str(
            "The harness may read these local files directly; they were not embedded in this prompt:\n\n",
        );
        for log in logs {
            prompt.push_str(&format!(
                "- {} ({} bytes, modified {})\n",
                log["path"].as_str().unwrap_or("?"),
                log["size"],
                log["modified_ms"]
            ));
        }
        prompt.push('\n');
    }
    prompt.push_str("## Evidence\n\n```json\n");
    prompt.push_str(&serde_json::to_string_pretty(incident).unwrap_or_default());
    prompt.push_str("\n```\n\n");
    prompt.push_str(
        "## Required output\n\nReturn JSON with:\n\
- `classification`: one of `likely_noise`, `benign`, `suspicious`, `malicious`, `unknown`\n\
- `confidence`: `low`, `medium`, or `high`\n\
- `reason`: short evidence-based explanation\n\
- `evidence`: array of specific observation IDs, paths, processes, or flow endpoints\n\
- `recommended_action`: concrete next step or `no action`\n\
- `needs_human_review`: boolean\n\
Do not recommend automatic deletion, quarantine, or allowlisting without human review.\n",
    );
    prompt
}

fn string(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FocusRule;

    fn incident(app: &str, path: &str) -> Value {
        json!({
            "id": "incident-1",
            "ts_ms": 1,
            "severity": "high",
            "title": "test",
            "pid": 42,
            "comm": app,
            "path": path,
            "details": {
                "actor": {
                    "comm": app,
                    "cwd": "/work/project",
                    "executable": format!("/usr/bin/{app}"),
                    "application": {"name": app},
                    "uid": 1000
                },
                "package_trust": {"status": "arch_signed_unmodified", "source": "arch_repo_signed", "validation": "pgp", "hash_match": true}
            }
        })
    }

    #[test]
    fn focus_matches_application_and_project_path() {
        let rule = FocusRule {
            name: "codex".into(),
            applications: vec!["codex".into()],
            paths: vec!["/work/project".into()],
            log_paths: Vec::new(),
        };
        assert!(focus_matches(
            &rule,
            "codex",
            "codex",
            "/usr/bin/codex",
            &["/work/project/file".into()],
            None
        ));
        assert!(!focus_matches(
            &rule,
            "codex",
            "codex",
            "/usr/bin/codex",
            &["/other/file".into()],
            None
        ));
    }

    #[test]
    fn known_harness_logs_are_detected_without_user_paths() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(".codex/log");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("session.jsonl"), b"{}\n").unwrap();
        let paths = detected_log_paths("codex", "codex", "/usr/bin/codex", None, Some(temp.path()));
        let files = describe_files(&paths);
        assert!(files.iter().any(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("session.jsonl"))
        }));
    }

    #[test]
    fn prompt_contains_package_trust_and_output_schema() {
        let value = bundle(
            &incident("codex", "/work/project/a"),
            &Config::default(),
            Some(Path::new("/home/alice")),
        );
        let prompt = value["prompt"].as_str().unwrap();
        assert!(prompt.contains("arch_signed_unmodified"));
        assert!(prompt.contains("likely_noise"));
        assert!(prompt.contains("Do not recommend automatic deletion"));
    }
}
