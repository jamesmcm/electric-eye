use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use crate::client;

struct Check {
    name: &'static str,
    status: &'static str,
    detail: String,
    hint: Option<String>,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: "ok",
            detail: detail.into(),
            hint: None,
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name,
            status: "warn",
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            name,
            status: "fail",
            detail: detail.into(),
            hint: Some(hint.into()),
        }
    }
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "hint": self.hint,
        })
    }
}

fn bytes(value: u64) -> String {
    electric_eye_core::humanize_bytes(value).to_string()
}

fn systemctl(verb: &str) -> String {
    Command::new("systemctl")
        .args([verb, "electric-eye.service"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn groups() -> String {
    Command::new("id")
        .arg("-nG")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn run(socket: &Path, json: bool) -> anyhow::Result<i32> {
    let mut checks = Vec::new();

    let active = systemctl("is-active");
    if active == "active" {
        checks.push(Check::ok("service_active", active));
    } else {
        checks.push(Check::fail(
            "service_active",
            format!("systemd: {active}"),
            "run: sudo systemctl start electric-eye.service",
        ));
    }
    let enabled = systemctl("is-enabled");
    if enabled == "enabled" {
        checks.push(Check::ok("service_enabled", enabled));
    } else {
        checks.push(Check::warn(
            "service_enabled",
            enabled,
            "enable it with: sudo systemctl enable --now electric-eye.service",
        ));
    }

    if let Some(parent) = socket.parent()
        && parent.exists()
    {
        checks.push(Check::ok(
            "socket_directory",
            format!("{}", parent.display()),
        ));
    } else {
        checks.push(Check::fail(
            "socket_directory",
            format!("missing {}", socket.display()),
            "start the service and verify RuntimeDirectory=electric-eye",
        ));
    }

    let status = client::request(socket, &json!({ "op": "status" }));
    let status_value = match status {
        Ok(value) => {
            checks.push(Check::ok(
                "daemon_query",
                format!(
                    "{} {} reachable",
                    value["daemon"].as_str().unwrap_or("daemon"),
                    value["version"].as_str().unwrap_or("?")
                ),
            ));
            Some(value)
        }
        Err(err) => {
            checks.push(Check::fail(
                "daemon_query",
                format!("{err:#}"),
                "check: systemctl status electric-eye; then check the socket path and permissions",
            ));
            None
        }
    };

    let current_groups = groups();
    if current_groups
        .split_whitespace()
        .any(|group| group == "electric-eye")
    {
        checks.push(Check::ok("group_access", current_groups));
    } else if status_value.is_some() {
        checks.push(Check::warn(
            "group_access",
            "current session is not in the electric-eye group; socket access works now, possibly via ACL",
            "run: sudo usermod -aG electric-eye \"$USER\" and log in again",
        ));
    } else {
        checks.push(Check::fail(
            "group_access",
            "not in the electric-eye group and the daemon is unreachable",
            "run: sudo usermod -aG electric-eye \"$USER\" and log in again",
        ));
    }

    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        checks.push(Check::ok("kernel_btf", "/sys/kernel/btf/vmlinux"));
    } else {
        checks.push(Check::fail(
            "kernel_btf",
            "kernel BTF is unavailable",
            "use a kernel with CONFIG_DEBUG_INFO_BTF=y",
        ));
    }
    let tracefs = [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ]
    .iter()
    .any(|path| std::fs::metadata(path).is_ok());
    let attached = status_value
        .as_ref()
        .and_then(|status| status["attached_probes"].as_array().map(Vec::len))
        .unwrap_or(0);
    if tracefs || attached > 0 {
        checks.push(Check::ok(
            "tracefs",
            if tracefs {
                "trace events readable by current user".to_string()
            } else {
                format!("not readable by current user; daemon reports {attached} attached probes")
            },
        ));
    } else {
        checks.push(Check::fail(
            "tracefs",
            "tracefs events are unavailable",
            "ensure tracefs/debugfs is mounted and the service has CAP_BPF/CAP_PERFMON",
        ));
    }

    if let Some(status) = &status_value {
        let loss = status["capture_loss"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let numbers: Vec<u64> = loss.iter().filter_map(Value::as_u64).collect();
        if numbers.len() >= 4 {
            if numbers[..3].iter().all(|n| *n == 0) {
                checks.push(Check::ok(
                    "capture_loss",
                    format!("ring/pending/identity loss: {:?}", &numbers[..3]),
                ));
            } else {
                checks.push(Check::fail(
                    "capture_loss",
                    format!("ring/pending/identity loss: {:?}", &numbers[..3]),
                    "reduce event volume or increase capture.ring_bytes; see docs/PERFORMANCE.md",
                ));
            }
            if numbers[3] == 0 {
                checks.push(Check::ok("path_uncertainty", "no unresolved-path events"));
            } else {
                checks.push(Check::warn(
                    "path_uncertainty",
                    format!("{} events have uncertain paths", numbers[3]),
                    "path uncertainty is not event loss; inspect with: electric-eye activity --json",
                ));
            }
        }
        let dropped = status["store"]["dropped"].as_u64().unwrap_or(0);
        if dropped == 0 {
            checks.push(Check::ok("store_drops", "0 storage drops"));
        } else {
            checks.push(Check::warn(
                "store_drops",
                format!("{dropped} storage drops"),
                "tune limits.store_queue/store_batch; see docs/PERFORMANCE.md",
            ));
        }
        let probes = status["attached_probes"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        let skipped = status["skipped_probes"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        if probes > 0 {
            checks.push(Check::ok("probes", format!("{probes} probes attached")));
        } else {
            checks.push(Check::fail(
                "probes",
                "no probes attached",
                "check kernel BTF, tracefs and service capabilities",
            ));
        }
        if skipped > 0 {
            checks.push(Check::warn(
                "skipped_probes",
                format!("{skipped} probes skipped"),
                "check the daemon journal for skipped-probe reasons",
            ));
        }
        if status["mcp_socket"].is_string() {
            checks.push(Check::ok(
                "mcp",
                status["mcp_socket"].as_str().unwrap_or_default(),
            ));
        } else {
            checks.push(Check::warn(
                "mcp",
                "MCP server is disabled",
                "remove --no-mcp or use --mcp-socket to enable agent access",
            ));
        }
    }

    match client::request(socket, &json!({ "op": "db" })) {
        Ok(db) => {
            let free = db["disk_free_bytes"].as_u64().unwrap_or(u64::MAX);
            let total = db["disk_total_bytes"].as_u64().unwrap_or(1);
            let percent = if total > 0 {
                free as f64 * 100.0 / total as f64
            } else {
                100.0
            };
            let detail = format!(
                "{} DB + {} WAL; {} free ({:.0}%)",
                bytes(db["db_bytes"].as_u64().unwrap_or(0)),
                bytes(db["wal_bytes"].as_u64().unwrap_or(0)),
                bytes(free),
                percent
            );
            if free < 10 * 1024 * 1024 * 1024 || percent < 10.0 {
                checks.push(Check::warn(
                    "storage",
                    detail,
                    "review retention and add ignore_paths; use: electric-eye db status",
                ));
            } else {
                checks.push(Check::ok("storage", detail));
            }
        }
        Err(err) => {
            checks.push(Check::warn(
                "storage",
                format!("database status unavailable: {err:#}"),
                "run with SQLite enabled or inspect the daemon journal",
            ));
        }
    }

    match client::request(socket, &json!({ "op": "config" })) {
        Ok(config) => {
            let text = config["toml"].as_str().unwrap_or_default();
            checks.push(Check::ok(
                "configuration",
                format!("{} bytes of effective TOML", text.len()),
            ));
        }
        Err(err) => {
            checks.push(Check::warn(
                "configuration",
                format!("could not read effective configuration: {err:#}"),
                "check the daemon config path and journal",
            ));
        }
    }

    match client::request(socket, &json!({ "op": "noise", "limit": 500 })) {
        Ok(noise) => {
            let count = noise["candidates"].as_array().map(Vec::len).unwrap_or(0);
            if count == 0 {
                checks.push(Check::ok("noise", "no obvious noise candidates"));
            } else {
                checks.push(Check::warn(
                    "noise",
                    format!("{count} likely noise candidates"),
                    "review with: electric-eye noise",
                ));
            }
        }
        Err(err) => {
            checks.push(Check::warn(
                "noise",
                format!("noise analysis unavailable: {err:#}"),
                "run: electric-eye noise after the daemon is healthy",
            ));
        }
    }

    let failed = checks.iter().any(|check| check.status == "fail");
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": !failed,
                "checks": checks.iter().map(Check::to_json).collect::<Vec<_>>(),
            }))?
        );
    } else {
        for check in &checks {
            println!("[{}] {}: {}", check.status, check.name, check.detail);
            if let Some(hint) = &check.hint {
                println!("       hint: {hint}");
            }
        }
        println!();
        println!(
            "{}",
            if failed {
                "doctor found failures; fix them before relying on capture"
            } else {
                "doctor checks passed with no failures"
            }
        );
    }
    Ok(if failed { 1 } else { 0 })
}
