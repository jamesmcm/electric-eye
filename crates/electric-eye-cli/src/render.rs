use electric_eye_core::humanize_bytes;
use serde_json::Value;
fn s(v: &Value) -> String {
    v.as_str().map(clean).unwrap_or_else(|| {
        if v.is_null() {
            "?".into()
        } else {
            v.to_string()
        }
    })
}
fn clean(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn rows<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn bytes(v: &Value) -> String {
    humanize_bytes(v.as_u64().unwrap_or(0))
}
fn when(v: &Value) -> String {
    let Some(ts) = v.as_u64() else {
        return "unknown time".into();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if ts > now + 1000 {
        return format!("at {ts}ms (future)");
    }
    let seconds = now.saturating_sub(ts) / 1000;
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h ago", seconds / 3600)
    } else {
        format!("{}d ago", seconds / 86400)
    }
}
fn arguments(p: &Value) -> String {
    if p["argv_captured"] == false {
        return "unavailable or disabled".into();
    }
    let args = rows(p, "argv")
        .iter()
        .map(|a| format!("{:?}", a.as_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{}{}",
        args,
        if p["argv_truncated"] == true {
            " [truncated]"
        } else {
            ""
        }
    )
}
fn event(entry: &Value) -> String {
    let e = &entry["event"];
    let app = entry["application"]["name"]
        .as_str()
        .or_else(|| e["comm"].as_str())
        .unwrap_or("unknown");
    let action = match e["event"].as_str().unwrap_or_default() {
        "exec" => format!("started {}", s(&e["exe"])),
        "fork" => format!("created child process {}", s(&e["pid"])),
        "exit" => "exited".into(),
        "file_read" => format!("opened {} for reading", s(&e["path"])),
        "file_open" => format!("{} {}", s(&e["kind"]), s(&e["path"])),
        "file_write" => format!(
            "{} {} ({}, {} calls)",
            if e["kind"] == "mmap" {
                "mapped writable"
            } else {
                "wrote"
            },
            s(&e["path"]),
            bytes(&e["bytes"]),
            s(&e["count"])
        ),
        "file_unlink" => format!("removed {}", s(&e["path"])),
        "file_rename" => format!("renamed {} -> {}", s(&e["from_path"]), s(&e["to_path"])),
        "traffic" => format!(
            "sent {}, received {} (process totals)",
            bytes(&e["sent"]),
            bytes(&e["recv"])
        ),
        "connect" | "accept" | "listen" => {
            let mut addr = [0u8; 16];
            for (i, byte) in rows(e, "addr").iter().take(16).enumerate() {
                addr[i] = byte.as_u64().unwrap_or(0) as u8;
            }
            let ip = match e["family"].as_u64() {
                Some(2) => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    addr[0], addr[1], addr[2], addr[3],
                ))),
                Some(10) => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr))),
                _ => None,
            };
            let port = if e["event"] == "listen" {
                &e["local_port"]
            } else {
                &e["remote_port"]
            };
            let endpoint = ip
                .map(|ip| {
                    std::net::SocketAddr::new(ip, port.as_u64().unwrap_or(0) as u16).to_string()
                })
                .unwrap_or_else(|| "unresolved endpoint".into());
            format!(
                "{} {}{}",
                s(&e["event"]),
                endpoint,
                e["hostname"]
                    .as_str()
                    .map(|n| format!(" ({})", clean(n)))
                    .unwrap_or_default()
            )
        }
        _ => s(e),
    };
    let outcome = entry["syscall_result"]
        .as_i64()
        .filter(|n| *n < 0)
        .map(|n| format!(" [FAILED errno={}]", -n))
        .unwrap_or_default();
    let uncertain = entry["path_resolution"]
        .as_str()
        .filter(|s| *s != "kernel")
        .map(|p| format!(" [{p} path]"))
        .unwrap_or_default();
    format!(
        "{}  {} pid {}  {}{}{}",
        when(&entry["ts_ms"]),
        clean(app),
        s(&e["pid"]),
        action,
        outcome,
        uncertain
    )
}
pub fn render(v: &Value) -> String {
    let mut out = Vec::new();
    if let Some(error) = v["error"].as_str() {
        return format!("Error: {}\n", clean(error));
    }
    if v["daemon"].is_string() {
        out.push(format!(
            "{} {} — running for {}s",
            s(&v["daemon"]),
            s(&v["version"]),
            s(&v["uptime_secs"])
        ));
        let counts: Vec<u64> = v["capture_loss"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(serde_json::Value::as_u64)
                    .collect()
            })
            .unwrap_or_default();
        let loss = counts.get(..3).unwrap_or(&counts);
        let uncertain = counts.get(3).copied().unwrap_or(0);
        out.push(format!(
            "{} events; capture losses {:?}; uncertain paths {}; storage drops {}",
            s(&v["events_total"]),
            loss,
            uncertain,
            s(&v["store"]["dropped"])
        ));
    }
    for p in rows(v, "processes") {
        out.push(format!(
            "{}  pid {}  {}  [{}]",
            s(&p["comm"]),
            s(&p["identity"]["pid"]),
            s(&p["executable"]),
            s(&p["source"])
        ));
        out.push(format!(
            "  ID: {}\n  Parent: {}\n  uid/euid: {}/{}",
            s(&p["id"]),
            p["parent"],
            s(&p["uid"]),
            s(&p["euid"])
        ));
        out.push(format!("  Arguments: {}", arguments(p)));
        out.push(format!(
            "  cwd: {}\n  cgroup: {}\n  unit: {} / {}",
            s(&p["cwd"]),
            s(&p["cgroup"]),
            s(&p["system_unit"]),
            s(&p["user_unit"])
        ));
        if !p["package"]["package"].is_null() {
            out.push(format!(
                "  Package: {} {}",
                s(&p["package"]["package"]["name"]),
                s(&p["package"]["package"]["version"])
            ));
        }
        if !p["application"].is_null() {
            out.push(format!(
                "  Application: {} ({})",
                s(&p["application"]["name"]),
                s(&p["application"]["reason"])
            ));
        }
        if !p["exited_ms"].is_null() {
            out.push(format!(
                "  Exit: code {} signal {}",
                s(&p["exit_code"]),
                s(&p["signal"])
            ));
        }
    }
    for exec in rows(v, "execs") {
        out.push(format!(
            "Exec generation {} — {}: {}\n  Arguments: {}",
            s(&exec["exec_id"]),
            when(&exec["first_seen_ms"]),
            s(&exec["executable"]),
            arguments(exec)
        ));
    }
    if v["inventory_truncated"] == true || v["execs_truncated"] == true {
        out.push("[history truncated; narrow the query using a stable process ID]".into());
    }
    for a in rows(v, "apps") {
        out.push(format!(
            "{}  {} events  sent {}  received {}\n  Application: {}",
            a["name"]
                .as_str()
                .map(clean)
                .unwrap_or_else(|| s(&a["comm"])),
            s(&a["events"]),
            bytes(&a["sent"]),
            bytes(&a["recv"]),
            s(&a["comm"])
        ));
        if let Some(contexts) = a["contexts"].as_array()
            && !contexts.is_empty()
        {
            out.push(format!(
                "  Contexts: {}",
                contexts.iter().map(s).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    for task in rows(v, "tasks") {
        out.push(format!(
            "{}  {}{} processes  {}\n  {}",
            s(&task["attribution"]["name"]),
            if task["processes_truncated"] == true {
                "at least "
            } else {
                ""
            },
            rows(task, "processes").len(),
            s(&task["attribution"]["reason"]),
            s(&task["attribution"]["task_id"])
        ));
    }
    for summary in rows(v, "overview") {
        out.push(s(&summary["text"]));
    }
    for e in rows(v, "activity") {
        out.push(event(e));
    }
    for e in rows(v, "events") {
        out.push(event(&e["entry"]));
    }
    for a in rows(v, "activities")
        .iter()
        .chain(rows(v, "persisted_activities"))
    {
        out.push(format!(
            "{}  {}  {} {} ({} events, {})",
            when(&a["bucket_ms"]),
            a["app_name"]
                .as_str()
                .map(clean)
                .unwrap_or_else(|| s(&a["app"])),
            s(&a["kind"]),
            s(&a["subject"]),
            s(&a["count"]),
            bytes(&a["bytes"])
        ));
    }
    for i in rows(v, "incidents") {
        let app = i["details"]["actor"]["application"]["name"]
            .as_str()
            .or_else(|| i["comm"].as_str())
            .unwrap_or("?");
        out.push(format!(
            "[{}] {}\n  {} pid {}  {}\n  Incident: {}",
            s(&i["severity"]),
            s(&i["title"]),
            clean(app),
            s(&i["pid"]),
            s(&i["path"]),
            s(&i["id"])
        ));
        if let Some(trust) = i["details"]["package_trust"].as_object() {
            out.push(format!(
                "  Binary trust: {} ({}; hash_match={})",
                trust.get("status").map(s).unwrap_or_else(|| "?".into()),
                trust.get("source").map(s).unwrap_or_else(|| "?".into()),
                trust.get("hash_match").map(s).unwrap_or_else(|| "?".into())
            ));
        }
        if i["details"]["rule"] == "bulk_mutation" {
            if let Some(argv) = i["details"]["actor"]["argv"].as_array() {
                let command = argv.iter().map(s).collect::<Vec<_>>().join(" ");
                out.push(format!("  Ran: {}", clean(&command)));
            }
            if let Some(files) = i["details"]["files"].as_array() {
                let shown = files.iter().take(8).map(s).collect::<Vec<_>>().join(", ");
                out.push(format!(
                    "  Changed: {}{}",
                    clean(&shown),
                    if files.len() > 8 { " …" } else { "" }
                ));
            }
        }
    }
    for f in rows(v, "flows") {
        let app = f["application"]["name"]
            .as_str()
            .map(clean)
            .unwrap_or_else(|| "unknown application".into());
        out.push(format!(
            "{} pid {} — {} {} -> {} [{}]\n  context: {}  role={} exposure={}\n  sent {}, received {}; duration {}ms; scope {}{}\n  Flow: {}",
            app,s(&f["owner"]["pid"]),s(&f["protocol"]),s(&f["local"]),s(&f["remote"]),s(&f["state"]),
            s(&f["network_context"]["label"]),s(&f["role"]),s(&f["exposure"]),
            bytes(&f["sent"]),bytes(&f["received"]),s(&f["duration_ms"]),s(&f["scope"]),
            f["errno"].as_i64().map(|n|format!("; errno {n}")).unwrap_or_default(),s(&f["id"])
        ));
        if f["partial_start"] == true {
            out.push(
                "  Partial observation: socket creation was not observed in this segment.".into(),
            );
        }
        if f["contributors_truncated"] == true {
            out.push("  [contributor list truncated; flow byte totals are complete]".into());
        }
        if let Some(contributors) = f["contributors"].as_object() {
            for c in contributors.values() {
                out.push(format!(
                    "  {} pid {}: sent {}, received {}",
                    s(&c["comm"]),
                    s(&c["process"]["pid"]),
                    bytes(&c["sent"]),
                    bytes(&c["received"])
                ));
            }
        }
    }
    for summary in rows(v, "summaries") {
        out.push(format!(
            "{}  [{}]\n  Summary: {}; {} evidence records{}",
            s(&summary["text"]),
            s(&summary["confidence"]),
            s(&summary["id"]),
            rows(summary, "evidence").len(),
            if summary["evidence_truncated"] == true {
                " [truncated]"
            } else {
                ""
            }
        ));
        for e in rows(summary, "evidence").iter().take(3) {
            if !e["observation"].is_null() {
                let mut entry = e.clone();
                entry["event"] = e["observation"].clone();
                out.push(format!("  {}", event(&entry)));
            } else if !e["flow_id"].is_null() {
                out.push(format!(
                    "  Flow: {} — {}",
                    s(&e["flow_id"]),
                    s(&e["relationship"])
                ));
            }
        }
        if rows(summary, "evidence").len() > 3 {
            out.push("  Use --json for all evidence.".into());
        }
    }
    if let Some(history) = v["history"].as_str() {
        out.push(format!("History: {}", clean(history)));
    }
    if out.is_empty() {
        out.push("No matching recorded activity.".into());
    }
    out.join("\n") + "\n"
}

pub fn db(v: &Value) -> String {
    if let Some(error) = v["error"].as_str() {
        return format!("Error: {}\n", clean(error));
    }
    let mut out = Vec::new();
    out.push(format!("Database: {}", s(&v["path"])));
    out.push(format!(
        "Size: {} main, {} WAL, {} SHM",
        bytes(&v["db_bytes"]),
        bytes(&v["wal_bytes"]),
        bytes(&v["shm_bytes"])
    ));
    out.push(format!(
        "Rows: {} raw events, {} activities, {} incidents, {} documents",
        s(&v["raw_events"]),
        s(&v["activities"]),
        s(&v["incidents"]),
        s(&v["documents_total"])
    ));
    if let Some(documents) = v["documents"].as_array()
        && !documents.is_empty()
    {
        out.push("Documents:".into());
        for document in documents {
            out.push(format!(
                "  {} {}",
                s(&document["collection"]),
                s(&document["count"])
            ));
        }
    }
    out.push(format!(
        "Retention: raw {} min; activity {}d; process {}d; flow {}d; summary {}d; heuristic summaries {}d",
        s(&v["retention"]["raw_retention_minutes"]),
        s(&v["retention"]["activity_retention_days"]),
        s(&v["retention"]["process_retention_days"]),
        s(&v["retention"]["flow_retention_days"]),
        s(&v["retention"]["summary_retention_days"]),
        s(&v["retention"]["noise_retention_days"])
    ));
    out.push(format!(
        "Incident retention: high {}d; medium {}d; low {}d",
        s(&v["retention"]["incident_high_retention_days"]),
        s(&v["retention"]["incident_medium_retention_days"]),
        s(&v["retention"]["incident_low_retention_days"])
    ));
    if !v["oldest_activity_ms"].is_null() || !v["newest_activity_ms"].is_null() {
        out.push(format!(
            "Activity window: {} to {}",
            when(&v["oldest_activity_ms"]),
            when(&v["newest_activity_ms"])
        ));
    }
    if let (Some(free), Some(total)) = (
        v["disk_free_bytes"].as_u64(),
        v["disk_total_bytes"].as_u64(),
    ) {
        let percent = if total > 0 {
            free as f64 * 100.0 / total as f64
        } else {
            0.0
        };
        out.push(format!(
            "Disk: {} free of {} ({:.1}% free)",
            humanize_bytes(free),
            humanize_bytes(total),
            percent
        ));
        if free < 10 * 1024 * 1024 * 1024 || percent < 10.0 {
            out.push("WARNING: low disk headroom; review retention and ignore_paths".into());
        }
    }
    out.push(format!(
        "Free pages: {} of {} ({} bytes/page)",
        s(&v["free_pages"]),
        s(&v["page_count"]),
        s(&v["page_size"])
    ));
    out.push(format!("Storage drops: {}", s(&v["dropped"])));
    out.join("\n") + "\n"
}

pub fn noise(v: &Value) -> String {
    if v["error"].is_string() {
        return render(v);
    }
    let mut out = vec!["Likely noise candidates:".to_string()];
    for candidate in rows(v, "candidates") {
        match candidate["kind"].as_str().unwrap_or_default() {
            "path" => out.push(format!(
                "  PATH  {}  {} events, {}, {} files",
                s(&candidate["value"]),
                s(&candidate["events"]),
                bytes(&candidate["bytes"]),
                s(&candidate["files"])
            )),
            "application" => {
                let top = rows(candidate, "top_rules")
                    .first()
                    .map(|rule| format!("{} ({})", s(&rule["title"]), s(&rule["count"])))
                    .unwrap_or_else(|| "unknown rule".into());
                out.push(format!(
                    "  APP   {}  {} incidents, mostly {}",
                    s(&candidate["value"]),
                    s(&candidate["incidents"]),
                    top
                ));
            }
            "correlation" => out.push(format!(
                "  HEUR  {}  {} summaries; often logs/caches/databases",
                s(&candidate["value"]),
                s(&candidate["summaries"])
            )),
            other => out.push(format!("  {other}  {}", s(&candidate["value"]))),
        }
    }
    if rows(v, "candidates").is_empty() {
        out.push("  none above the current thresholds".into());
    }
    out.push(String::new());
    out.push("Suggested configuration (review before applying):".into());
    out.push(
        v["suggested_config"]
            .as_str()
            .unwrap_or("# no suggestion")
            .trim_end()
            .to_string(),
    );
    out.push(String::new());
    out.push(format!(
        "Window: {} activity rows, {} incidents, {} summaries. {}",
        s(&v["window"]["activity_rows"]),
        s(&v["window"]["incidents"]),
        s(&v["window"]["summaries"]),
        s(&v["history"])
    ));
    out.join("\n") + "\n"
}

pub fn tree(v: &Value) -> String {
    if v["error"].is_string() {
        return render(v);
    }
    use std::collections::{HashMap, HashSet};
    fn id(p: &Value) -> String {
        format!(
            "{}:{}:{}",
            p["boot_id"].as_str().unwrap_or_default(),
            p["pid"],
            p["start_ns"]
        )
    }
    let all = rows(v, "processes");
    let index: HashMap<_, _> = all
        .iter()
        .filter_map(|p| p["id"].as_str().map(|id| (id.to_string(), p)))
        .collect();
    fn visit(
        p: &Value,
        depth: usize,
        all: &[Value],
        seen: &mut HashSet<String>,
        out: &mut Vec<String>,
    ) {
        let key = p["id"].as_str().unwrap_or_default().to_string();
        if !seen.insert(key.clone()) {
            return;
        }
        out.push(format!(
            "{}{} pid {}{} [{}]",
            "  ".repeat(depth),
            s(&p["comm"]),
            s(&p["identity"]["pid"]),
            if p["exited_ms"].is_null() {
                String::new()
            } else {
                format!(" exited {}", s(&p["exit_code"]))
            },
            s(&p["source"])
        ));
        if depth >= 128 {
            out.push("[tree depth limit]".into());
            return;
        }
        for child in all {
            if !child["parent"].is_null() && id(&child["parent"]) == key {
                visit(child, depth + 1, all, seen, out);
            }
        }
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for p in all {
        if p["parent"].is_null() || !index.contains_key(&id(&p["parent"])) {
            visit(p, 0, all, &mut seen, &mut out);
        }
    }
    for p in all {
        visit(p, 0, all, &mut seen, &mut out);
    }
    if out.is_empty() {
        "No matching recorded processes.\n".into()
    } else {
        out.join("\n") + "\n"
    }
}
pub fn focus(v: &Value) -> String {
    let mut out = vec!["FOCUS                 ACTIVITY  FLOWS  INCIDENTS  APPS".to_string()];
    for rule in rows(v, "focus") {
        let apps = rule["apps"]
            .as_array()
            .map(|apps| apps.iter().take(3).map(s).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        out.push(format!(
            "{:<21} {:<9} {:<6} {:<10} {}",
            truncate(&s(&rule["name"]), 21),
            s(&rule["activity"]),
            s(&rule["flows"]),
            s(&rule["incidents"]),
            truncate(&apps, 40)
        ));
        for log in rows(rule, "harness_logs").iter().take(3) {
            out.push(format!(
                "  log: {} ({} bytes)",
                s(&log["path"]),
                s(&log["size"])
            ));
        }
    }
    if out.len() == 1 {
        out.push("No focus rules configured. Add [[focus]] entries to the configuration.".into());
    }
    out.join("\n") + "\n"
}

pub fn investigate(v: &Value) -> String {
    v["prompt"]
        .as_str()
        .map(str::to_string)
        .or_else(|| v["investigation"]["prompt"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{}\n", s(&v["error"])))
}

pub fn netns(v: &Value) -> String {
    let mut out = vec![
        "CONTEXT                 KIND      VPN  UNIT                 PUBLISHED   APPS  LISTENERS  FLOWS  SENT / RECV".to_string(),
    ];
    for context in rows(v, "contexts") {
        let label = s(&context["label"]);
        let kind = s(&context["kind"]);
        let unit = context["unit"].as_str().unwrap_or("-").to_string();
        let vpn = if context["vpn"] == true { "yes" } else { "no" };
        let published = context["published_ports"]
            .as_array()
            .map(|ports| ports.iter().map(s).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        let apps = context["apps"]
            .as_array()
            .map(|apps| apps.iter().take(2).map(s).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        out.push(format!(
            "{:<23} {:<9} {:<4} {:<20} {:<11} {:<5} {:<10} {:<6} {} / {}",
            truncate(&label, 23),
            truncate(&kind, 9),
            vpn,
            truncate(&unit, 20),
            truncate(&published, 11),
            context["apps"].as_array().map(Vec::len).unwrap_or(0),
            context["listeners"],
            context["flows"],
            bytes(&context["sent"]),
            bytes(&context["received"]),
        ));
        if !apps.is_empty() {
            out.push(format!("  apps: {apps}"));
        }
        if let Some(vopono_apps) = context["vopono_apps"].as_array()
            && !vopono_apps.is_empty()
        {
            out.push(format!(
                "  vopono apps: {}",
                vopono_apps.iter().map(s).collect::<Vec<_>>().join(",")
            ));
        }
        if let Some(container) = context["container"].as_object() {
            let mappings = container["port_mappings"]
                .as_array()
                .map(|mappings| {
                    mappings
                        .iter()
                        .map(|mapping| {
                            format!(
                                "{}->{}/{}",
                                s(&mapping["host_port"]),
                                s(&mapping["container_port"]),
                                s(&mapping["protocol"])
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            out.push(format!(
                "  container: runtime={} id={} image={} published={} mappings={}",
                container
                    .get("runtime")
                    .map(s)
                    .unwrap_or_else(|| "-".into()),
                container
                    .get("id")
                    .map(s)
                    .map(|id| truncate(&id, 12))
                    .unwrap_or_else(|| "-".into()),
                container.get("image").map(s).unwrap_or_else(|| "-".into()),
                container
                    .get("published_ports")
                    .map(s)
                    .unwrap_or_else(|| "-".into()),
                if mappings.is_empty() { "-" } else { &mappings },
            ));
        }
        if let Some(vopono) = context["vopono"].as_object() {
            let forwarded = vopono
                .get("port_forwarding")
                .and_then(Value::as_object)
                .map(|forwarding| {
                    format!(
                        "{} provider={} automatic={} updated={}",
                        forwarding.get("port").map(s).unwrap_or_else(|| "-".into()),
                        forwarding
                            .get("provider")
                            .map(s)
                            .unwrap_or_else(|| "-".into()),
                        forwarding
                            .get("automatic")
                            .map(s)
                            .unwrap_or_else(|| "-".into()),
                        forwarding
                            .get("updated")
                            .map(s)
                            .unwrap_or_else(|| "-".into()),
                    )
                })
                .unwrap_or_else(|| "-".into());
            out.push(format!(
                "  vopono: provider={} protocol={} server={} forwarded={}",
                vopono.get("provider").map(s).unwrap_or_else(|| "-".into()),
                vopono.get("protocol").map(s).unwrap_or_else(|| "-".into()),
                vopono.get("server").map(s).unwrap_or_else(|| "-".into()),
                forwarded,
            ));
            if let Some(health) = vopono.get("health").and_then(Value::as_object) {
                let checked = health
                    .get("checked_at")
                    .and_then(Value::as_u64)
                    .map(|secs| when(&Value::from(secs.saturating_mul(1000))))
                    .unwrap_or_else(|| "-".into());
                let age = health
                    .get("handshake_age_seconds")
                    .and_then(Value::as_u64)
                    .map(|seconds| format!("{seconds}s"))
                    .unwrap_or_else(|| "-".into());
                out.push(format!(
                    "  vopono health: state={} checked={} handshake_age={} reconnects={} error={}",
                    health.get("state").map(s).unwrap_or_else(|| "-".into()),
                    checked,
                    age,
                    health
                        .get("reconnect_attempts")
                        .map(s)
                        .unwrap_or_else(|| "-".into()),
                    health
                        .get("last_error")
                        .and_then(Value::as_str)
                        .unwrap_or("-"),
                ));
            }
        }
    }
    if out.len() == 1 {
        out.push("No network contexts observed.".into());
    }
    out.join("\n") + "\n"
}

pub fn explain_network(v: &Value) -> String {
    let mut out = vec![
        format!("Network explanation: {}", s(&v["selector"])),
        format!("Verdict: {}", s(&v["verdict"])),
        format!(
            "Flows: {} (inbound {}, outbound {}, UDP peer {})",
            s(&v["flows"]),
            s(&v["inbound"]),
            s(&v["outbound"]),
            s(&v["udp_peer"])
        ),
        format!(
            "Data: sent {}, received {}; file events {}, writes {}",
            bytes(&v["total_sent"]),
            bytes(&v["total_received"]),
            s(&v["file_events"]),
            s(&v["file_writes"])
        ),
    ];
    if let Some(last) = v["last_seen_ms"].as_u64() {
        out.push(format!(
            "Last network observation: {}",
            when(&Value::from(last))
        ));
    }
    if let Some(last) = v["last_file_ms"].as_u64().filter(|last| *last > 0) {
        out.push(format!(
            "Last file observation: {}",
            when(&Value::from(last))
        ));
    }
    let listeners = rows(v, "listeners");
    if !listeners.is_empty() {
        out.push("Listeners:".into());
        for listener in listeners {
            out.push(format!(
                "  {}  exposure={}  context={}  published={}",
                s(&listener["local"]),
                s(&listener["exposure"]),
                s(&listener["context"]),
                s(&listener["published"])
            ));
        }
    }
    let roles = rows(v, "roles");
    if !roles.is_empty() {
        out.push("Roles:".into());
        for role in roles {
            out.push(format!(
                "  {:<12} flows={:<5} sent={:<10} received={}",
                s(&role["role"]),
                s(&role["flows"]),
                bytes(&role["sent"]),
                bytes(&role["received"])
            ));
        }
    }
    let contexts = rows(v, "contexts");
    if !contexts.is_empty() {
        out.push("Contexts:".into());
        for context in contexts {
            out.push(format!(
                "  {}  flows={} listeners={} published={}",
                s(&context["label"]),
                s(&context["flows"]),
                s(&context["listeners"]),
                s(&context["published_ports"])
            ));
        }
    }
    if let Some(caveat) = v["caveat"].as_str() {
        out.push(format!("Caveat: {caveat}"));
    }
    out.join("\n") + "\n"
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        value.to_string()
    } else {
        value
            .chars()
            .take(width.saturating_sub(1))
            .collect::<String>()
            + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn renders_restored_history_execs_and_flow_attribution_without_json_dumps() {
        let text = render(
            &json!({"persisted_activities":[{"bucket_ms":1,"app":"app:id","app_name":"Editor","kind":"file.write","subject":"/work/a","count":1,"bytes":4}],"execs":[{"exec_id":2,"executable":"/usr/bin/test","argv_captured":false}],"flows":[{"id":"flow-1","protocol":"TCP","owner":{"pid":42},"application":{"name":"Editor"},"duration_ms":200,"errno":111}]}),
        );
        assert!(text.contains("Editor") && text.contains("/work/a"));
        assert!(text.contains("Exec generation 2") && text.contains("unavailable or disabled"));
        assert!(
            text.contains("pid 42")
                && text.contains("duration 200ms")
                && text.contains("errno 111")
        );
        let tree_error = tree(&json!({"error":"failed query"}));
        assert!(tree_error.contains("failed query"));
    }
    #[test]
    fn renders_ipv6_endpoints_for_activity() {
        let text = render(
            &json!({"activity":[{"event":{"event":"connect","family":10,"addr":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"remote_port":443}}]}),
        );
        assert!(text.contains("connect [::1]:443"));
    }
    #[test]
    fn renders_vopono_health_and_container_port_mappings() {
        let text = netns(&json!({
            "contexts": [{
                "label": "vopono:vo_test",
                "kind": "vopono",
                "vpn": true,
                "unit": "vopono.service",
                "published_ports": [43161],
                "apps": ["Transmission"],
                "vopono_apps": ["transmission-gtk"],
                "listeners": 1,
                "flows": 4,
                "sent": 10,
                "received": 20,
                "vopono": {
                    "provider": "airvpn",
                    "protocol": "wireguard",
                    "server": "copernicus",
                    "port_forwarding": {"port": 52000, "provider": "airvpn", "automatic": true, "updated": 1},
                    "health": {"state": "Connected", "checked_at": 1, "handshake_age_seconds": 12, "reconnect_attempts": 0, "last_error": null}
                },
                "container": {
                    "runtime": "docker",
                    "id": "0123456789abcdef",
                    "image": "nginx:latest",
                    "published_ports": [8080],
                    "port_mappings": [{"host_port": 8080, "container_port": 80, "protocol": "tcp"}]
                }
            }]
        }));
        assert!(text.contains("forwarded=52000"));
        assert!(text.contains("vopono health: state=Connected"));
        assert!(text.contains("container: runtime=docker"));
        assert!(text.contains("mappings=8080->80/tcp"), "{text}");
    }

    #[test]
    fn renders_noise_candidates_and_suggested_config() {
        let text = noise(&json!({
            "candidates": [
                {"kind":"path","value":"/home/a/workload_runs","events":1200,"bytes":5000,"files":12},
                {"kind":"application","value":"hermes","incidents":92,"top_rules":[{"title":"Novel network destination","count":90}]},
                {"kind":"correlation","value":"download_like","summaries":4}
            ],
            "suggested_config": "ignore_paths = [\"/home/a/workload_runs\"]",
            "window": {"activity_rows": 100, "incidents": 10, "summaries": 5},
            "history": "persisted and recent"
        }));
        assert!(text.contains("PATH"));
        assert!(text.contains("APP"));
        assert!(text.contains("HEUR"));
        assert!(text.contains("ignore_paths"));
    }

    #[test]
    fn marks_failed_and_uncertain_events() {
        let text = render(
            &json!({"activity":[{"ts_ms":1,"syscall_result":-13,"path_resolution":"lexical","event":{"event":"file_read","comm":"test","path":"/secret\nspoof"}}]}),
        );
        assert!(text.contains("FAILED errno=13"));
        assert!(text.contains("lexical path"));
        assert!(!text.contains("\nspoof"));
    }
}
