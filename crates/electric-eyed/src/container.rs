//! Read-only container metadata for network context.
//!
//! Docker and Podman keep their per-container JSON metadata on disk; LXC keeps
//! its configuration under `/var/lib/lxc`. Published host ports are read from
//! those records. LXC has no standard published-port field, so its static
//! addresses are matched against host DNAT rules as a best-effort fallback.
//! Nothing is started, entered or modified.

use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
pub struct ContainerContext {
    pub runtime: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub published_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub port_mappings: Vec<PortMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

pub fn inspect(
    runtime: &str,
    name_or_id: &str,
    uid: u32,
    home: Option<&Path>,
) -> Option<ContainerContext> {
    match runtime {
        "docker" => inspect_docker(name_or_id, uid, home),
        "podman" => inspect_podman(name_or_id, uid, home),
        "lxc" => inspect_lxc(name_or_id, uid, home),
        _ => None,
    }
}

fn inspect_docker(name_or_id: &str, uid: u32, home: Option<&Path>) -> Option<ContainerContext> {
    let mut roots = vec![PathBuf::from("/var/lib/docker/containers")];
    roots.extend(container_roots(uid, home, ".local/share/docker/containers"));
    let mut found = None;
    for root in roots {
        if let Some(dir) = find_container_dir(&root, name_or_id) {
            found = Some(dir);
            break;
        }
    }
    let dir = found?;
    let id = dir.file_name()?.to_string_lossy().to_string();
    let config = read_json(dir.join("config.v2.json"));
    let host = read_json(dir.join("hostconfig.json"));
    let mut context = ContainerContext {
        runtime: "docker".into(),
        id,
        name: None,
        image: None,
        addresses: Vec::new(),
        published_ports: Vec::new(),
        port_mappings: Vec::new(),
        source: Some(dir.display().to_string()),
    };
    if let Some(config) = config.as_ref() {
        context.name = config["Name"]
            .as_str()
            .map(|name| name.trim_start_matches('/').to_string())
            .filter(|name| !name.is_empty());
        context.image = config["Config"]["Image"].as_str().map(str::to_string);
        context.addresses = json_addresses(&config["NetworkSettings"]);
        context
            .port_mappings
            .extend(port_mappings(&config["NetworkSettings"]["Ports"]));
    }
    if let Some(host) = host.as_ref() {
        context
            .port_mappings
            .extend(port_mappings(&host["PortBindings"]));
    }
    context.published_ports = context
        .port_mappings
        .iter()
        .map(|mapping| mapping.host_port)
        .collect();
    context.port_mappings.sort();
    context.port_mappings.dedup();
    context.published_ports.sort_unstable();
    context.published_ports.dedup();
    context.addresses.sort();
    context.addresses.dedup();
    Some(context)
}

fn inspect_podman(name_or_id: &str, uid: u32, home: Option<&Path>) -> Option<ContainerContext> {
    let mut roots = vec![PathBuf::from(
        "/var/lib/containers/storage/overlay-containers",
    )];
    if let Some(home) = home {
        roots.push(home.join(".local/share/containers/storage/overlay-containers"));
    } else if uid != 0
        && let Some(home) = crate::net_context::home_for_uid(uid)
    {
        roots.push(home.join(".local/share/containers/storage/overlay-containers"));
    }
    for root in roots {
        let Some(dir) = find_container_dir(&root, name_or_id) else {
            continue;
        };
        let id = dir.file_name()?.to_string_lossy().to_string();
        let config = read_json(dir.join("userdata/config.json"));
        let host = read_json(dir.join("userdata/hostconfig.json"));
        let mut context = ContainerContext {
            runtime: "podman".into(),
            id,
            name: None,
            image: None,
            addresses: Vec::new(),
            published_ports: Vec::new(),
            port_mappings: Vec::new(),
            source: Some(dir.display().to_string()),
        };
        if let Some(config) = config.as_ref() {
            context.name = config["annotations"]["io.podman.annotations.name"]
                .as_str()
                .or_else(|| config["name"].as_str())
                .map(str::to_string);
            context.image = config["image"].as_str().map(str::to_string);
            context.addresses = json_addresses(&config["network"]);
            context
                .port_mappings
                .extend(port_mappings(&config["network"]["Ports"]));
        }
        if let Some(host) = host.as_ref() {
            context.name = context
                .name
                .take()
                .or_else(|| host["Name"].as_str().map(str::to_string));
            context.image = context
                .image
                .take()
                .or_else(|| host["Image"].as_str().map(str::to_string));
            context
                .port_mappings
                .extend(port_mappings(&host["PortBindings"]));
            context.addresses.extend(json_addresses(&host["Networks"]));
        }
        context.published_ports = context
            .port_mappings
            .iter()
            .map(|mapping| mapping.host_port)
            .collect();
        context.port_mappings.sort();
        context.port_mappings.dedup();
        context.published_ports.sort_unstable();
        context.published_ports.dedup();
        context.addresses.sort();
        context.addresses.dedup();
        return Some(context);
    }
    None
}

fn inspect_lxc(name: &str, uid: u32, home: Option<&Path>) -> Option<ContainerContext> {
    let mut roots = vec![PathBuf::from("/var/lib/lxc")];
    roots.extend(container_roots(uid, home, ".local/share/lxc"));
    let path = roots
        .into_iter()
        .map(|root| root.join(name).join("config"))
        .find(|path| path.is_file())?;
    let text = std::fs::read_to_string(&path).ok()?;
    let addresses = lxc_addresses(&text);
    let mut mappings = Vec::new();
    if !addresses.is_empty()
        && let Some(rules) = run_iptables_nat()
    {
        mappings = published_mappings_from_iptables(&rules, &addresses);
    }
    let mut published_ports = mappings
        .iter()
        .map(|mapping| mapping.host_port)
        .collect::<Vec<_>>();
    published_ports.sort_unstable();
    published_ports.dedup();
    Some(ContainerContext {
        runtime: "lxc".into(),
        id: name.to_string(),
        name: Some(name.to_string()),
        image: None,
        addresses,
        published_ports,
        port_mappings: mappings,
        source: Some(path.display().to_string()),
    })
}

fn container_roots(uid: u32, home: Option<&Path>, suffix: &str) -> Vec<PathBuf> {
    let home = home
        .map(Path::to_path_buf)
        .or_else(|| crate::net_context::home_for_uid(uid));
    home.map(|home| vec![home.join(suffix)]).unwrap_or_default()
}

fn find_container_dir(root: &Path, name_or_id: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut fallback = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name == name_or_id {
            return Some(path);
        }
        if name.starts_with(name_or_id) {
            fallback = Some(path);
        }
    }
    fallback
}

fn read_json(path: PathBuf) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn port_mappings(value: &Value) -> Vec<PortMapping> {
    let mut mappings = Vec::new();
    let Some(bindings) = value.as_object() else {
        return mappings;
    };
    for (container, binding) in bindings {
        let Some(binding) = binding.as_array() else {
            continue;
        };
        let (container_port, protocol) = container
            .split_once('/')
            .and_then(|(port, protocol)| Some((port.parse::<u16>().ok()?, protocol)))
            .unwrap_or((0, "tcp"));
        if container_port == 0 {
            continue;
        }
        for entry in binding {
            if let Some(host_port) = entry["HostPort"]
                .as_str()
                .and_then(|port| port.parse::<u16>().ok())
                .or_else(|| {
                    entry["HostPort"]
                        .as_u64()
                        .and_then(|port| u16::try_from(port).ok())
                })
                .filter(|port| *port != 0)
            {
                mappings.push(PortMapping {
                    host_port,
                    container_port,
                    protocol: protocol.to_string(),
                });
            }
        }
    }
    mappings.sort();
    mappings.dedup();
    mappings
}

fn json_addresses(value: &Value) -> Vec<String> {
    let mut addresses = Vec::new();
    if let Some(address) = value["IPAddress"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        addresses.push(address.to_string());
    }
    if let Some(address) = value["GlobalIPv6Address"]
        .as_str()
        .filter(|value| !value.is_empty())
    {
        addresses.push(address.to_string());
    }
    if let Some(networks) = value["Networks"].as_object() {
        for network in networks.values() {
            for key in ["IPAddress", "GlobalIPv6Address"] {
                if let Some(address) = network[key].as_str().filter(|value| !value.is_empty()) {
                    addresses.push(address.to_string());
                }
            }
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

fn lxc_addresses(text: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.contains("ipv4.address") && !key.contains("ipv6.address") {
            continue;
        }
        let value = value.trim().split('/').next().unwrap_or_default().trim();
        if !value.is_empty() && value != "auto" {
            addresses.push(value.to_string());
        }
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

fn published_mappings_from_iptables(text: &str, addresses: &[String]) -> Vec<PortMapping> {
    let mut mappings = Vec::new();
    for line in text.lines() {
        if !line.contains("DNAT") && !line.contains("dnat") {
            continue;
        }
        let Some(destination) = line
            .split("--to-destination")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
        else {
            continue;
        };
        let host = if let Some(rest) = destination.strip_prefix('[') {
            rest.split(']').next().unwrap_or(destination)
        } else {
            destination
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(destination)
        };
        if !addresses.iter().any(|address| address == host) {
            continue;
        }
        let Some(host_port) = line
            .split("--dport")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u16>().ok())
        else {
            continue;
        };
        let container_port = destination
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(0);
        let protocol = line
            .split("-p")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .unwrap_or("tcp")
            .to_string();
        mappings.push(PortMapping {
            host_port,
            container_port,
            protocol,
        });
    }
    mappings.sort();
    mappings.dedup();
    mappings
}

fn run_iptables_nat() -> Option<String> {
    let mut child = Command::new("iptables")
        .args(["-t", "nat", "-S"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_metadata_yields_name_image_address_and_published_ports() {
        let config = serde_json::json!({
            "Name": "/web",
            "Config": {"Image": "nginx:latest"},
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
                "Networks": {"bridge": {"IPAddress": "172.17.0.2"}}
            }
        });
        let host = serde_json::json!({
            "PortBindings": {"443/tcp": [{"HostIp": "", "HostPort": "8443"}]}
        });
        let mappings = port_mappings(&config["NetworkSettings"]["Ports"]);
        assert_eq!(mappings[0].host_port, 8080);
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[0].protocol, "tcp");
        let mappings = port_mappings(&host["PortBindings"]);
        assert_eq!(mappings[0].host_port, 8443);
        assert_eq!(mappings[0].container_port, 443);
        assert_eq!(
            json_addresses(&config["NetworkSettings"]),
            vec!["172.17.0.2"]
        );
        assert_eq!(config["Config"]["Image"], "nginx:latest");
    }

    #[test]
    fn podman_port_bindings_are_parsed() {
        let host = serde_json::json!({
            "Name": "db",
            "Image": "postgres:17",
            "PortBindings": {
                "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15432"}],
                "5432/udp": []
            }
        });
        let mappings = port_mappings(&host["PortBindings"]);
        assert_eq!(mappings[0].host_port, 15432);
        assert_eq!(mappings[0].container_port, 5432);
    }

    #[test]
    fn lxc_addresses_and_iptables_dnat_are_matched() {
        let config = "lxc.net.0.type = veth\nlxc.net.0.ipv4.address = 10.0.3.100/24\n";
        assert_eq!(lxc_addresses(config), vec!["10.0.3.100"]);
        let rules = "\
-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.3.100:80
-A PREROUTING -p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.0.3.100:443
-A PREROUTING -p tcp -m tcp --dport 9000 -j DNAT --to-destination 10.0.3.200:80
";
        let mappings = published_mappings_from_iptables(rules, &["10.0.3.100".into()]);
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].host_port, 8080);
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[1].host_port, 8443);
        assert_eq!(mappings[1].container_port, 443);
    }
}
