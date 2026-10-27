use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn flow_context(flow: &Value) -> &Value {
    &flow["network_context"]
}

fn has_semantics(flow: &Value) -> bool {
    flow["network_context"].is_object() && flow["role"].is_string()
}

fn context_id(flow: &Value) -> String {
    let context = flow_context(flow);
    context["id"]
        .as_str()
        .or_else(|| context["label"].as_str())
        .unwrap_or("legacy")
        .to_string()
}

fn context_label(flow: &Value) -> String {
    let context = flow_context(flow);
    context["label"]
        .as_str()
        .or_else(|| context["id"].as_str())
        .unwrap_or("legacy (pre-context)")
        .to_string()
}

fn local_port(flow: &Value) -> Option<u16> {
    flow["local_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .or_else(|| {
            flow["local"]
                .as_str()
                .and_then(|local| local.rsplit(':').next())
                .and_then(|port| port.parse().ok())
        })
}

fn listener_rows(flows: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    let mut listeners = Vec::new();
    for flow in flows {
        let role = flow["role"].as_str().unwrap_or_default();
        let inferred = flow["direction"].as_str() == Some("inbound")
            && flow["exposure"].as_str() == Some("published");
        if role != "listener" && !inferred {
            continue;
        }
        let port = local_port(flow).unwrap_or(0);
        let key = format!("{}:{port}", context_id(flow));
        if !seen.insert(key) {
            continue;
        }
        listeners.push(json!({
            "local": flow["local"],
            "local_port": port,
            "exposure": flow["exposure"],
            "context_id": context_id(flow),
            "context": context_label(flow),
            "published": flow_context(flow)["published_ports"].clone(),
            "state": flow["state"],
        }));
    }
    listeners
}

fn context_matches(flow: &Value, filter: &str) -> bool {
    let context = flow_context(flow);
    let filter = filter.to_ascii_lowercase();
    [
        context["id"].as_str(),
        context["label"].as_str(),
        context["kind"].as_str(),
        context["name"].as_str(),
        context["unit"].as_str(),
    ]
    .into_iter()
    .flatten()
    .any(|value| value.to_ascii_lowercase().contains(&filter))
}

fn role_matches(flow: &Value, filter: &str) -> bool {
    let filter = filter.to_ascii_lowercase();
    flow["role"]
        .as_str()
        .is_some_and(|role| role.to_ascii_lowercase().contains(&filter))
        || (filter == "listener"
            && flow["direction"].as_str() == Some("inbound")
            && flow["exposure"].as_str() == Some("published"))
}

pub fn filter_flows(value: &mut Value, netns: Option<&str>, role: Option<&str>) {
    let Some(rows) = value["flows"].as_array_mut() else {
        return;
    };
    if netns.is_none() && role.is_none() {
        return;
    }
    rows.retain(|flow| {
        netns.is_none_or(|filter| context_matches(flow, filter))
            && role.is_none_or(|filter| role_matches(flow, filter))
    });
}

fn flow_matches_selector(flow: &Value, selector: &str) -> bool {
    let selector = selector.to_ascii_lowercase();
    let app = &flow["application"];
    let owner = &flow["owner"];
    if app["name"]
        .as_str()
        .is_some_and(|value| value.to_ascii_lowercase().contains(&selector))
        || app["id"]
            .as_str()
            .is_some_and(|value| value.to_ascii_lowercase().contains(&selector))
        || owner["pid"]
            .as_u64()
            .is_some_and(|pid| pid.to_string() == selector)
    {
        return true;
    }
    flow["contributors"]
        .as_object()
        .is_some_and(|contributors| {
            contributors.values().any(|contributor| {
                contributor["comm"]
                    .as_str()
                    .is_some_and(|value| value.to_ascii_lowercase().contains(&selector))
                    || contributor["executable"]
                        .as_str()
                        .is_some_and(|value| value.to_ascii_lowercase().contains(&selector))
            })
        })
}

pub fn contexts(flows: &[Value]) -> Value {
    let listeners = listener_rows(flows);
    let mut listener_counts: BTreeMap<String, u64> = BTreeMap::new();
    for listener in &listeners {
        let key = listener["context_id"]
            .as_str()
            .unwrap_or("legacy")
            .to_string();
        *listener_counts.entry(key).or_insert(0) += 1;
    }

    let mut contexts: BTreeMap<String, Value> = BTreeMap::new();
    for flow in flows {
        let context = flow_context(flow);
        let key = context_id(flow);
        let label = context_label(flow);
        let entry = contexts.entry(key).or_insert_with(|| {
            json!({
                "id": context["id"],
                "kind": if context.is_object() { context["kind"].clone() } else { json!("legacy") },
                "label": label,
                "name": context["name"],
                "unit": context["unit"],
                "vpn": context["vpn"],
                "published_ports": context["published_ports"],
                "vopono": context["vopono"],
                "container": context["container"],
                "flows": 0,
                "listeners": 0,
                "inbound": 0,
                "outbound": 0,
                "udp_peer": 0,
                "sent": 0,
                "received": 0,
                "apps": [],
                "vopono_apps": [],
                "last_seen_ms": 0,
            })
        });
        entry["flows"] = (entry["flows"].as_u64().unwrap_or(0) + 1).into();
        let role = flow["role"].as_str().unwrap_or_default();
        match flow["direction"].as_str().unwrap_or_default() {
            "inbound" => {
                entry["inbound"] = (entry["inbound"].as_u64().unwrap_or(0) + 1).into();
            }
            "outbound" => {
                entry["outbound"] = (entry["outbound"].as_u64().unwrap_or(0) + 1).into();
            }
            _ => {}
        }
        if role == "udp_peer" {
            entry["udp_peer"] = (entry["udp_peer"].as_u64().unwrap_or(0) + 1).into();
        }
        entry["sent"] =
            (entry["sent"].as_u64().unwrap_or(0) + flow["sent"].as_u64().unwrap_or(0)).into();
        entry["received"] = (entry["received"].as_u64().unwrap_or(0)
            + flow["received"].as_u64().unwrap_or(0))
        .into();
        let last = flow["last_seen_ms"].as_u64().unwrap_or(0);
        if last > entry["last_seen_ms"].as_u64().unwrap_or(0) {
            entry["last_seen_ms"] = last.into();
        }
        if let Some(app) = flow["application"]["name"].as_str() {
            let apps = entry["apps"].as_array_mut().expect("apps array");
            if !apps.iter().any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case(app))
            }) {
                apps.push(app.into());
            }
        }
        if let Some(vopono_apps) = context["vopono"]["applications"].as_array() {
            let apps = entry["vopono_apps"]
                .as_array_mut()
                .expect("vopono apps array");
            for app in vopono_apps {
                let Some(command) = app["command"].as_str() else {
                    continue;
                };
                if !apps.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(command))
                }) {
                    apps.push(command.into());
                }
            }
        }
    }
    for (key, count) in listener_counts {
        if let Some(entry) = contexts.get_mut(&key) {
            entry["listeners"] = count.into();
        }
    }
    let mut rows: Vec<Value> = contexts.into_values().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row["flows"].as_u64().unwrap_or(0)));
    json!({"contexts": rows, "count": rows.len(), "listeners": listeners})
}

fn file_event_count(activity: Option<&Value>) -> (u64, u64, u64) {
    let Some(activity) = activity else {
        return (0, 0, 0);
    };
    let mut files = 0_u64;
    let mut writes = 0_u64;
    let mut last = 0_u64;
    if let Some(rows) = activity["events"].as_array() {
        for row in rows {
            let kind = row["kind"].as_str().unwrap_or_default();
            if kind.starts_with("file.") {
                files += 1;
                if kind.contains("write")
                    || kind.contains("unlink")
                    || kind.contains("rename")
                    || kind.contains("truncate")
                {
                    writes += 1;
                }
                last = last.max(row["ts_ms"].as_u64().unwrap_or(0));
            }
        }
    }
    (files, writes, last)
}

fn role_summary(flows: &[Value]) -> Value {
    let mut roles: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    for flow in flows {
        let role = flow["role"].as_str().unwrap_or("unknown").to_string();
        let entry = roles.entry(role).or_default();
        entry.0 += 1;
        entry.1 += flow["sent"].as_u64().unwrap_or(0);
        entry.2 += flow["received"].as_u64().unwrap_or(0);
    }
    json!(
        roles
            .into_iter()
            .map(|(role, (flows, sent, received))| {
                json!({"role": role, "flows": flows, "sent": sent, "received": received})
            })
            .collect::<Vec<_>>()
    )
}

pub fn explain(flows: &[Value], activity: Option<&Value>, selector: &str) -> Value {
    let selected: Vec<&Value> = flows
        .iter()
        .filter(|flow| flow_matches_selector(flow, selector))
        .collect();
    let semantic: Vec<Value> = selected
        .iter()
        .filter(|flow| has_semantics(flow))
        .map(|flow| (*flow).clone())
        .collect();
    let legacy_flows = selected.len().saturating_sub(semantic.len());
    let context_report = contexts(&semantic);
    let listeners = listener_rows(&semantic);
    let total_sent: u64 = semantic
        .iter()
        .map(|flow| flow["sent"].as_u64().unwrap_or(0))
        .sum();
    let total_received: u64 = semantic
        .iter()
        .map(|flow| flow["received"].as_u64().unwrap_or(0))
        .sum();
    let (file_events, file_writes, last_file_ms) = file_event_count(activity);
    let udp_peer = semantic
        .iter()
        .filter(|flow| flow["role"].as_str() == Some("udp_peer"))
        .count() as u64;
    let inbound = semantic
        .iter()
        .filter(|flow| flow["direction"].as_str() == Some("inbound"))
        .count() as u64;
    let outbound = semantic
        .iter()
        .filter(|flow| flow["direction"].as_str() == Some("outbound"))
        .count() as u64;
    let last_seen_ms = semantic
        .iter()
        .map(|flow| flow["last_seen_ms"].as_u64().unwrap_or(0))
        .max()
        .unwrap_or(0);

    let verdict = if selected.is_empty() {
        "no recent network activity observed for this selector"
    } else if semantic.is_empty() {
        "only historical flows without semantic context were found; wait for fresh observations or increase --since"
    } else if !listeners.is_empty() && file_events == 0 && total_sent + total_received < 1_048_576 {
        "idle listener / control-plane only: listeners are present, but no file activity and no sustained data-plane traffic were observed; inbound attempts may be probes or discovery"
    } else if !listeners.is_empty() && file_events == 0 {
        "listening without observed file activity; traffic may be control-plane, discovery, or probes"
    } else if udp_peer > 0 && file_events == 0 && total_sent + total_received < 1_048_576 {
        "UDP peer/discovery activity without file I/O; this is consistent with DHT or µTP rather than bulk transfer"
    } else if file_events > 0 && total_sent + total_received > 0 {
        "active application traffic with observed file activity"
    } else {
        "network activity observed; review roles and contexts for details"
    };

    json!({
        "selector": selector,
        "verdict": verdict,
        "flows": selected.len(),
        "semantic_flows": semantic.len(),
        "legacy_flows": legacy_flows,
        "inbound": inbound,
        "outbound": outbound,
        "udp_peer": udp_peer,
        "listeners": listeners,
        "contexts": context_report["contexts"],
        "roles": role_summary(&semantic),
        "total_sent": total_sent,
        "total_received": total_received,
        "file_events": file_events,
        "file_writes": file_writes,
        "last_file_ms": last_file_ms,
        "last_seen_ms": last_seen_ms,
        "caveat": "Roles are port/state heuristics; DHT, tracker and BitTorrent payloads are not inspected. Historical flows observed before semantic enrichment are excluded from the verdict.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(app: &str, role: &str, direction: &str, sent: u64, received: u64) -> Value {
        json!({
            "application": {"name": app, "id": format!("executable:{app}")},
            "owner": {"pid": 42},
            "network_context": {
                "id": "netns:9",
                "kind": "vopono",
                "name": "vo_test",
                "label": "vopono:vo_test",
                "unit": "vopono.service",
                "vpn": true,
                "published_ports": [43161]
            },
            "role": role,
            "direction": direction,
            "exposure": if direction == "inbound" { "published" } else { "n/a" },
            "local": "0.0.0.0:43161",
            "remote": "203.0.113.1:5555",
            "state": if role == "listener" { "listening" } else { "established" },
            "sent": sent,
            "received": received,
            "last_seen_ms": 100,
            "contributors": {}
        })
    }

    #[test]
    fn contexts_group_flows_and_published_ports() {
        let flows = vec![
            flow("Transmission", "listener", "inbound", 0, 0),
            flow("Transmission", "inbound", "inbound", 10, 20),
        ];
        let report = contexts(&flows);
        assert_eq!(report["count"], 1);
        assert_eq!(report["contexts"][0]["listeners"], 1);
        assert_eq!(report["contexts"][0]["inbound"], 2);
        assert_eq!(report["contexts"][0]["published_ports"][0], 43161);
    }

    #[test]
    fn idle_listener_verdict_is_explicit() {
        let flows = vec![flow("Transmission", "listener", "inbound", 0, 0)];
        let report = explain(&flows, None, "Transmission");
        assert!(
            report["verdict"]
                .as_str()
                .unwrap()
                .contains("idle listener")
        );
        assert_eq!(report["listeners"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn selector_and_filters_are_case_insensitive() {
        let mut value = json!({"flows": [
            flow("Transmission", "listener", "inbound", 0, 0),
            flow("Firefox", "outbound", "outbound", 100, 200)
        ]});
        filter_flows(&mut value, Some("VOPONO"), Some("outbound"));
        assert_eq!(value["flows"].as_array().unwrap().len(), 1);
        assert_eq!(value["flows"][0]["application"]["name"], "Firefox");
    }

    #[test]
    fn listener_filter_includes_published_inbound_without_a_listen_event() {
        let mut value = json!({"flows": [
            flow("Transmission", "inbound", "inbound", 10, 20),
            flow("Firefox", "outbound", "outbound", 100, 200)
        ]});
        filter_flows(&mut value, Some("vopono"), Some("listener"));
        assert_eq!(value["flows"].as_array().unwrap().len(), 1);
        assert_eq!(value["flows"][0]["application"]["name"], "Transmission");
    }

    #[test]
    fn file_activity_changes_the_verdict() {
        let flows = vec![flow("Transmission", "inbound", "inbound", 10_000, 5_000)];
        let activity = json!({"events": [
            {"kind": "file.write", "ts_ms": 200}
        ]});
        let report = explain(&flows, Some(&activity), "Transmission");
        assert_eq!(report["file_events"], 1);
        assert!(report["verdict"].as_str().unwrap().contains("active"));
    }
}
