//! Read-only vopono namespace metadata.
//!
//! vopono's status/MCP surface is derived from user-owned lockfiles under
//! `~/.config/vopono/locks`. Reading those files directly avoids coupling to a
//! particular vopono CLI/daemon version and does not require running a
//! subprocess from the monitor. Only the small, documented fields needed for
//! network context are parsed; the files remain the source of truth.

use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize)]
pub struct VoponoContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<VoponoApplication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<VoponoPortForwarding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host_forwarded_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VoponoPortForwarding {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct VoponoApplication {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

pub fn read_namespace(home: &Path, namespace: &str) -> Option<VoponoContext> {
    let dir = home.join(".config/vopono/locks").join(namespace);
    if !dir.is_dir() {
        return None;
    }
    let mut context = VoponoContext::default();
    let mut applications = BTreeSet::new();
    let mut primary = None;

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return None;
    };
    for entry in entries.flatten().take(4096) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == "port-forwarding.json" {
            if let Ok(text) = crate::metadata::read_text(&path, 256 * 1024)
                && let Some((port, updated)) = json_sidecar(&text)
            {
                let forwarding = context.port_forwarding.get_or_insert_with(Default::default);
                forwarding.port = port;
                forwarding.updated = updated;
            }
            continue;
        }
        if name == "health.json" {
            if let Ok(text) = crate::metadata::read_text(&path, 256 * 1024) {
                context.health = parse_health(&text);
            }
            continue;
        }
        if let Some(pid) = name
            .strip_prefix("client-")
            .and_then(|pid| pid.parse().ok())
        {
            if !process_in_namespace(pid, namespace) {
                continue;
            }
            let text = crate::metadata::read_text(&path, 256 * 1024).ok();
            let command = text.as_deref().and_then(parse_command);
            applications.insert(VoponoApplication {
                pid: Some(pid),
                command,
            });
            continue;
        }
        if name.chars().all(|character| character.is_ascii_digit()) {
            primary = crate::metadata::read_text(&path, 256 * 1024).ok();
        }
    }

    if let Some(text) = primary {
        context.provider = field_ident(&text, "provider");
        context.protocol = field_ident(&text, "protocol");
        context.server = field_quoted(&text, "server");
        context.open_ports = field_ports(&text, "open_ports");
        context.host_forwarded_ports = field_ports(&text, "host_forwarded_ports");
        if context.port_forwarding.is_none() {
            context.port_forwarding = field_port_forwarding(&text);
        }
        if applications.is_empty()
            && let Some(pid) = field_u32(&text, "application_pid")
        {
            applications.insert(VoponoApplication {
                pid: Some(pid),
                command: parse_command(&text),
            });
        }
    }

    context.applications = applications.into_iter().collect();
    if context.provider.is_none()
        && context.protocol.is_none()
        && context.applications.is_empty()
        && context.open_ports.is_empty()
        && context.host_forwarded_ports.is_empty()
        && context.port_forwarding.is_none()
        && context.health.is_none()
    {
        return None;
    }
    Some(context)
}

/// Find the vopono namespace that owns `pid` using the per-application client
/// lockfile names. This is used when a process environment is unavailable.
pub fn namespace_for_pid(home: &Path, pid: u32) -> Option<String> {
    let root = home.join(".config/vopono/locks");
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten().take(4096) {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        if dir.join(format!("client-{pid}")).is_file() {
            return entry.file_name().to_str().map(str::to_string);
        }
    }
    None
}

fn process_in_namespace(pid: u32, namespace: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let process = std::fs::metadata(format!("/proc/{pid}/ns/net"));
    let target = std::fs::metadata(format!("/var/run/netns/{namespace}"));
    match (process, target) {
        (Ok(process), Ok(target)) => process.dev() == target.dev() && process.ino() == target.ino(),
        (Ok(_), Err(_)) => false,
        _ => false,
    }
}

fn parse_command(text: &str) -> Option<String> {
    let value = field_plain_quoted(text, "command")?;
    Some(
        value
            .split_whitespace()
            .next()
            .unwrap_or(&value)
            .to_string(),
    )
}

fn field_plain_quoted(text: &str, key: &str) -> Option<String> {
    let rest = text
        .split_once(&format!("{key}:\""))
        .map(|(_, rest)| rest)?;
    let end = rest.find('\"')?;
    Some(unescape(&rest[..end]))
}

fn field_ident(text: &str, key: &str) -> Option<String> {
    let rest = text.split_once(&format!("{key}:")).map(|(_, rest)| rest)?;
    let value = rest.split([',', ')', '\n']).next()?.trim();
    if value.is_empty() || value == "None" {
        None
    } else {
        Some(value.to_ascii_lowercase())
    }
}

fn field_quoted(text: &str, key: &str) -> Option<String> {
    let rest = text
        .split_once(&format!("{key}:Some(\""))
        .map(|(_, rest)| rest)?;
    let end = rest.find("\")")?;
    Some(unescape(&rest[..end]))
}

fn field_u32(text: &str, key: &str) -> Option<u32> {
    let rest = text
        .split_once(&format!("{key}:Some("))
        .map(|(_, rest)| rest)?;
    let digits: String = rest
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn field_ports(text: &str, key: &str) -> Vec<u16> {
    let Some(rest) = text.split_once(&format!("{key}:[")).map(|(_, rest)| rest) else {
        return Vec::new();
    };
    let end = rest.find(']').unwrap_or(rest.len());
    let mut ports: Vec<u16> = rest[..end]
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .filter(|port| *port != 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn field_port_forwarding(text: &str) -> Option<VoponoPortForwarding> {
    let rest = text.split_once("port_forwarding:Some((")?.1;
    let digits: String = rest
        .split_once("port:")
        .map(|(_, rest)| rest)?
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    let port = digits.parse().ok()?;
    Some(VoponoPortForwarding {
        port,
        provider: field_ident(rest, "provider"),
        automatic: field_bool(rest, "automatic"),
        updated: None,
    })
}

fn field_bool(text: &str, key: &str) -> Option<bool> {
    let rest = text.split_once(&format!("{key}:")).map(|(_, rest)| rest)?;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_sidecar(text: &str) -> Option<(u16, Option<u64>)> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let port = value["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())?;
    Some((port, value["updated"].as_u64()))
}

fn parse_health(text: &str) -> Option<serde_json::Value> {
    let mut value: serde_json::Value = serde_json::from_str(text).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.saturating_sub(value["checked_at"].as_u64().unwrap_or(0)) > 60 {
        value["state"] = serde_json::json!("Degraded");
        value["last_error"] =
            serde_json::json!("Monitoring result is stale; daemon may have stopped");
    }
    Some(value)
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            out.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else {
            out.push(character);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY: &str = r#"(ns:(name:"vo_test",provider:AirVPN,protocol:Wireguard,state:(server:Some("copernicus"),port_forwarding:None,open_ports:[43161,8080],host_forwarded_ports:[9000])),start:1,command:"transmission-gtk",application_pid:Some(42))"#;
    const CLIENT: &str = r#"(ns:(name:"vo_test",provider:AirVPN,protocol:Wireguard,state:(server:Some("copernicus"))),start:1,command:"firefox --new-window",application_pid:None)"#;

    #[test]
    fn parses_primary_lock_metadata() {
        assert_eq!(field_ident(PRIMARY, "provider").as_deref(), Some("airvpn"));
        assert_eq!(
            field_ident(PRIMARY, "protocol").as_deref(),
            Some("wireguard")
        );
        assert_eq!(
            field_quoted(PRIMARY, "server").as_deref(),
            Some("copernicus")
        );
        assert_eq!(field_ports(PRIMARY, "open_ports"), vec![8080, 43161]);
        assert_eq!(field_ports(PRIMARY, "host_forwarded_ports"), vec![9000]);
        assert_eq!(parse_command(PRIMARY).as_deref(), Some("transmission-gtk"));
        assert_eq!(parse_command(CLIENT).as_deref(), Some("firefox"));
        assert_eq!(field_u32(PRIMARY, "application_pid"), Some(42));
    }

    #[test]
    fn parses_forwarded_port_sidecar() {
        assert_eq!(
            json_sidecar(r#"{"port":51234,"updated":1}"#),
            Some((51234, Some(1)))
        );
        let forwarding = field_port_forwarding(
            r#"...port_forwarding:Some((provider:AirVPN,port:51234,automatic:true))..."#,
        )
        .unwrap();
        assert_eq!(forwarding.port, 51234);
        assert_eq!(forwarding.provider.as_deref(), Some("airvpn"));
        assert_eq!(forwarding.automatic, Some(true));
    }

    #[test]
    fn reads_namespace_metadata_health_and_renewed_port() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join(".config/vopono/locks/vo_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("1017"),
            r#"(ns:(name:"vo_test",provider:AirVPN,protocol:Wireguard,state:(server:Some("copernicus"),port_forwarding:Some((provider:AirVPN,port:51234,automatic:true)),open_ports:[43161],host_forwarded_ports:[9000])),start:1,command:"transmission-gtk",application_pid:Some(42))"#,
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(
            dir.join("health.json"),
            format!(
                r#"{{"state":"Connected","checked_at":{now},"last_successful_probe":{now},"handshake_age_seconds":12,"reconnect_attempts":0,"last_error":null}}"#
            ),
        )
        .unwrap();
        std::fs::write(
            dir.join("port-forwarding.json"),
            r#"{"port":52000,"updated":123}"#,
        )
        .unwrap();
        let context = read_namespace(temp.path(), "vo_test").unwrap();
        assert_eq!(context.provider.as_deref(), Some("airvpn"));
        assert_eq!(context.protocol.as_deref(), Some("wireguard"));
        assert_eq!(context.server.as_deref(), Some("copernicus"));
        assert_eq!(context.port_forwarding.as_ref().unwrap().port, 52000);
        assert_eq!(context.port_forwarding.as_ref().unwrap().updated, Some(123));
        assert_eq!(context.open_ports, vec![43161]);
        assert_eq!(context.host_forwarded_ports, vec![9000]);
        assert_eq!(context.health.as_ref().unwrap()["state"], "Connected");
        assert_eq!(context.applications[0].pid, Some(42));
    }

    #[test]
    fn stale_health_is_marked_degraded() {
        let health =
            parse_health(r#"{"state":"Connected","checked_at":1,"last_error":null}"#).unwrap();
        assert_eq!(health["state"], "Degraded");
        assert!(health["last_error"].as_str().unwrap().contains("stale"));
    }

    #[test]
    fn missing_fields_are_not_invented() {
        assert_eq!(field_ident("provider:None,", "provider"), None);
        assert_eq!(
            field_ports("no ports here", "open_ports"),
            Vec::<u16>::new()
        );
        assert_eq!(field_quoted("server:None", "server"), None);
    }
}
