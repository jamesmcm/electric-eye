//! Human-readable context for a network namespace.
//!
//! The kernel gives us the namespace inode. That is enough to correlate
//! sockets, but not enough to explain them. This module resolves the inode to
//! the host, a vopono VPN namespace, a container runtime, or another named
//! namespace using read-only `/proc`, `/run/netns` and runtime metadata.
//!
//! Only `VOPONO_*` environment keys are read. The raw environment is never
//! stored or exposed.

use crate::process::ProcessRecord;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize)]
pub struct NetworkContext {
    pub id: String,
    pub inode: u64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    pub vpn: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub namespace_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub published_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub published_container_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vopono: Option<crate::vopono::VoponoContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<crate::container::ContainerContext>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl NetworkContext {
    fn new(inode: u64, kind: &str) -> Self {
        let mut context = Self {
            id: format!("netns:{inode}"),
            inode,
            kind: kind.into(),
            name: None,
            label: kind.into(),
            unit: None,
            cgroup: None,
            vpn: false,
            namespace_addresses: Vec::new(),
            host_addresses: Vec::new(),
            published_ports: Vec::new(),
            published_container_ports: Vec::new(),
            vopono: None,
            container: None,
            evidence: Vec::new(),
        };
        context.refresh_label();
        context
    }

    pub fn host(inode: u64) -> Self {
        let mut context = Self::new(inode, "host");
        context.name = Some("host".into());
        context.evidence.push("daemon network namespace".into());
        context.refresh_label();
        context
    }

    pub fn fallback(inode: u64) -> Self {
        let mut context = Self::new(inode, "namespace");
        context.evidence.push("namespace inode".into());
        context.refresh_label();
        context
    }

    fn refresh_label(&mut self) {
        self.label = match (&self.kind[..], self.name.as_deref()) {
            ("host", _) => "host".into(),
            (kind, Some(name)) if !name.is_empty() && name != kind => format!("{kind}:{name}"),
            (kind, _) => kind.into(),
        };
    }

    fn set_name(&mut self, name: String) {
        if !name.is_empty() {
            self.name = Some(name);
            self.refresh_label();
        }
    }

    fn add_evidence(&mut self, evidence: &str) {
        if !self.evidence.iter().any(|item| item == evidence) {
            self.evidence.push(evidence.into());
        }
    }
}

#[derive(Default)]
struct VoponoEnv {
    namespace: Option<String>,
    namespace_addresses: Vec<String>,
    host_addresses: Vec<String>,
    published_ports: Vec<u16>,
}

type ContextRequest = (u64, Option<ProcessRecord>);
type ContextResult = (u64, NetworkContext);

pub struct Resolver {
    cache: HashMap<u64, (Instant, NetworkContext)>,
    ttl: Duration,
    host_inode: u64,
    worker: Option<(SyncSender<ContextRequest>, Receiver<ContextResult>)>,
    pending: HashSet<u64>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl Resolver {
    pub fn new(ttl: Duration) -> Self {
        use std::os::unix::fs::MetadataExt;
        let host_inode = std::fs::metadata("/proc/self/ns/net")
            .map(|metadata| metadata.ino())
            .unwrap_or(0);
        Self {
            cache: HashMap::new(),
            ttl,
            host_inode,
            worker: None,
            pending: HashSet::new(),
        }
    }

    pub fn resolve(&mut self, inode: u64, process: Option<&ProcessRecord>) -> NetworkContext {
        if inode == 0 {
            return NetworkContext::fallback(inode);
        }
        if inode == self.host_inode {
            return NetworkContext::host(inode);
        }
        if let Some((_, rx)) = &self.worker {
            while let Ok((loaded, context)) = rx.try_recv() {
                self.pending.remove(&loaded);
                self.cache.insert(loaded, (Instant::now(), context));
            }
        }
        if let Some((at, context)) = self.cache.get(&inode)
            && at.elapsed() < self.ttl
        {
            return context.clone();
        }
        if self.cache.len() >= 4096 {
            self.cache.retain(|_, (at, _)| at.elapsed() < self.ttl);
            if self.cache.len() >= 4096 {
                self.cache.clear();
            }
        }
        if self.worker.is_none() {
            let (tx, requests) = sync_channel::<ContextRequest>(32);
            let (results, rx) = sync_channel(32);
            let ttl = self.ttl;
            if std::thread::Builder::new()
                .name("electric-eye-net-context".into())
                .spawn(move || {
                    let mut builder = Self::new(ttl);
                    while let Ok((inode, process)) = requests.recv() {
                        let context = builder.build(inode, process.as_ref());
                        if results.send((inode, context)).is_err() {
                            break;
                        }
                    }
                })
                .is_err()
            {
                return NetworkContext::fallback(inode);
            }
            self.worker = Some((tx, rx));
        }
        let (tx, _) = self.worker.as_ref().unwrap();
        if self.pending.len() < 32
            && !self.pending.contains(&inode)
            && tx.try_send((inode, process.cloned())).is_ok()
        {
            self.pending.insert(inode);
        }
        // Runtime/user metadata is optional enrichment. Never wait on a remote
        // filesystem or a user-controlled file while draining kernel events.
        NetworkContext::fallback(inode)
    }

    fn build(&mut self, inode: u64, process: Option<&ProcessRecord>) -> NetworkContext {
        let mut context = NetworkContext::fallback(inode);

        if let Some((kind, name)) = named_namespace(inode) {
            context = NetworkContext::new(inode, &kind);
            context.set_name(name);
            context.add_evidence("named network namespace");
        }

        if let Some(process) = process {
            context.unit = process.system_unit.clone();
            context.cgroup = process.cgroup.clone();
            if let Some(env) = read_vopono_env(&process.identity) {
                apply_vopono(&mut context, env);
            }
            if process.system_unit.as_deref() == Some("vopono.service")
                || process
                    .cgroup
                    .as_deref()
                    .is_some_and(|cgroup| cgroup.contains("vopono.service"))
            {
                context.kind = "vopono".into();
                context.vpn = true;
                context.add_evidence("vopono.service cgroup");
                context.refresh_label();
            }
            if let Some((kind, name)) = process
                .cgroup
                .as_deref()
                .and_then(runtime_from_cgroup)
                .or_else(|| process.system_unit.as_deref().and_then(runtime_from_cgroup))
            {
                if context.kind == "namespace" || context.kind == "host" {
                    context.kind = kind.clone();
                    context.set_name(name.clone());
                    context.add_evidence("container cgroup");
                } else if context.name.is_none() {
                    context.set_name(name.clone());
                }
                if matches!(kind.as_str(), "docker" | "podman" | "lxc") {
                    let home = home_for_uid(process.uid);
                    if let Some(info) =
                        crate::container::inspect(&kind, &name, process.uid, home.as_deref())
                    {
                        merge_container(&mut context, info);
                    }
                }
            }
        }

        if context.kind == "vopono"
            && let Some(process) = process
            && let Some(home) = home_for_uid(process.uid)
        {
            let namespace = context
                .name
                .clone()
                .or_else(|| crate::vopono::namespace_for_pid(&home, process.identity.pid));
            if let Some(namespace) = namespace
                && let Some(info) = crate::vopono::read_namespace(&home, &namespace)
            {
                merge_vopono(&mut context, info);
            }
        }

        if context.unit.is_none() {
            context.unit = context.cgroup.as_deref().and_then(unit_from_cgroup);
        }
        context.refresh_label();
        context
    }
}

fn merge_container(context: &mut NetworkContext, info: crate::container::ContainerContext) {
    context.published_ports.extend(&info.published_ports);
    context.namespace_addresses.extend(info.addresses.clone());
    context.published_container_ports.extend(
        info.port_mappings
            .iter()
            .map(|mapping| mapping.container_port),
    );
    context.published_ports.sort_unstable();
    context.published_ports.dedup();
    context.published_container_ports.sort_unstable();
    context.published_container_ports.dedup();
    dedup(&mut context.namespace_addresses);
    if let Some(name) = &info.name {
        context.set_name(name.clone());
    }
    context.container = Some(info);
    context.add_evidence("container metadata");
}

fn merge_vopono(context: &mut NetworkContext, info: crate::vopono::VoponoContext) {
    context.published_ports.extend(&info.open_ports);
    context.published_ports.extend(&info.host_forwarded_ports);
    if let Some(forwarding) = &info.port_forwarding {
        context.published_ports.push(forwarding.port);
    }
    context.published_ports.sort_unstable();
    context.published_ports.dedup();
    context.vopono = Some(info);
    context.add_evidence("vopono lockfile");
}

pub(crate) fn home_for_uid(uid: u32) -> Option<std::path::PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 7 && fields[2].parse::<u32>().ok() == Some(uid) {
            return Some(std::path::PathBuf::from(fields[5]));
        }
    }
    None
}

fn read_vopono_env(identity: &crate::api::ProcessIdentity) -> Option<VoponoEnv> {
    use std::io::Read;
    let pid = identity.pid;
    let ticks = (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as u64;
    let expected = identity.start_ns / (1_000_000_000 / ticks);
    if crate::enrich::process_stat(pid)?.start_ticks != expected {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(format!("/proc/{pid}/environ"))
        .ok()?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 1024 * 1024 || crate::enrich::process_stat(pid)?.start_ticks != expected {
        return None;
    }
    if bytes.is_empty() {
        return None;
    }
    let mut env = VoponoEnv::default();
    for entry in bytes.split(|byte| *byte == 0) {
        let Ok(entry) = std::str::from_utf8(entry) else {
            continue;
        };
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        match key {
            "VOPONO_NS" => env.namespace = Some(value.to_string()),
            "VOPONO_NS_IP" | "VOPONO_NS_IPV6" => {
                if !value.is_empty() {
                    env.namespace_addresses.push(value.to_string());
                }
            }
            "VOPONO_HOST_IP" | "VOPONO_HOST_IPV6" => {
                if !value.is_empty() {
                    env.host_addresses.push(value.to_string());
                }
            }
            "VOPONO_OPEN_PORTS" | "VOPONO_HOST_FORWARDED_PORTS" => {
                env.published_ports.extend(parse_ports(value));
            }
            _ => {}
        }
    }
    if env.namespace.is_none()
        && env.namespace_addresses.is_empty()
        && env.host_addresses.is_empty()
        && env.published_ports.is_empty()
    {
        None
    } else {
        Some(env)
    }
}

fn apply_vopono(context: &mut NetworkContext, env: VoponoEnv) {
    context.kind = "vopono".into();
    context.vpn = true;
    if let Some(namespace) = env.namespace {
        context.set_name(namespace);
    }
    context.namespace_addresses.extend(env.namespace_addresses);
    context.host_addresses.extend(env.host_addresses);
    context.published_ports.extend(env.published_ports);
    dedup(&mut context.namespace_addresses);
    dedup(&mut context.host_addresses);
    context.published_ports.sort_unstable();
    context.published_ports.dedup();
    context.add_evidence("VOPONO_NS environment");
    context.refresh_label();
}

fn parse_ports(value: &str) -> Vec<u16> {
    value
        .split(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .filter_map(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .collect()
}

fn dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn named_namespace(inode: u64) -> Option<(String, String)> {
    for root in ["/run/netns", "/var/run/netns"] {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            if let Ok(target) = std::fs::read_link(&path)
                && let Some(target) = target.to_str()
                && let Some(value) = target.strip_prefix("net:[")
                && value.trim_end_matches(']').parse::<u64>().ok() == Some(inode)
            {
                return Some(("namespace".into(), name));
            }
            if fs_inode(&path) == Some(inode) {
                return Some(("namespace".into(), name));
            }
        }
    }

    // Docker bind-mounts each sandbox namespace here. The mount point inode is
    // the nsfs inode, so it can be matched without entering the namespace.
    if let Ok(entries) = std::fs::read_dir("/var/run/docker/netns") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let short = short_id(&name);
            if fs_inode(&entry.path()) == Some(inode) {
                return Some(("docker".into(), short));
            }
        }
    }
    None
}

fn fs_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|metadata| metadata.ino())
}

fn runtime_from_cgroup(cgroup: &str) -> Option<(String, String)> {
    for part in cgroup.split('/').rev() {
        if let Some(value) = part
            .strip_prefix("docker-")
            .or_else(|| part.strip_prefix("docker/"))
        {
            return Some(("docker".into(), short_id(value.trim_end_matches(".scope"))));
        }
        if let Some(value) = part.strip_prefix("libpod-") {
            return Some(("podman".into(), short_id(value.trim_end_matches(".scope"))));
        }
        if let Some(value) = part
            .strip_prefix("lxc.payload.")
            .or_else(|| part.strip_prefix("lxc/"))
        {
            return Some(("lxc".into(), value.to_string()));
        }
        if part == "vopono.service" {
            return Some(("vopono".into(), "vopono".into()));
        }
        if part.starts_with("kubepods") {
            return Some(("kubernetes".into(), part.to_string()));
        }
    }
    if cgroup.contains("/docker/") {
        return cgroup
            .split('/')
            .find(|part| part.len() >= 12 && part.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|id| ("docker".into(), short_id(id)));
    }
    None
}

fn unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .split('/')
        .rev()
        .find(|part| part.ends_with(".service") || part.ends_with(".scope"))
        .map(str::to_string)
}

fn short_id(value: &str) -> String {
    let value = value.trim();
    if value.len() > 12 {
        value[..12].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vopono_environment_produces_a_vpn_context() {
        let mut context = NetworkContext::fallback(4026533414);
        apply_vopono(
            &mut context,
            VoponoEnv {
                namespace: Some("vo_ar_test".into()),
                namespace_addresses: vec!["10.200.1.2".into()],
                host_addresses: vec!["10.200.1.1".into()],
                published_ports: vec![43161],
            },
        );
        assert_eq!(context.kind, "vopono");
        assert_eq!(context.label, "vopono:vo_ar_test");
        assert!(context.vpn);
        assert_eq!(context.published_ports, vec![43161]);
        assert_eq!(context.namespace_addresses, vec!["10.200.1.2"]);
    }

    #[test]
    fn published_ports_accept_common_separators() {
        assert_eq!(parse_ports("43161, 8080;443 0"), vec![43161, 8080, 443]);
        assert_eq!(parse_ports(""), Vec::<u16>::new());
    }

    #[test]
    fn container_metadata_merges_into_context() {
        let mut context = NetworkContext::fallback(1);
        context.kind = "docker".into();
        merge_container(
            &mut context,
            crate::container::ContainerContext {
                runtime: "docker".into(),
                id: "0123456789abcdef".into(),
                name: Some("web".into()),
                image: Some("nginx:latest".into()),
                addresses: vec!["172.17.0.2".into()],
                published_ports: vec![8080],
                port_mappings: vec![crate::container::PortMapping {
                    host_port: 8080,
                    container_port: 80,
                    protocol: "tcp".into(),
                }],
                source: None,
            },
        );
        assert_eq!(context.label, "docker:web");
        assert_eq!(context.published_ports, vec![8080]);
        assert_eq!(context.published_container_ports, vec![80]);
        assert_eq!(context.namespace_addresses, vec!["172.17.0.2"]);
        assert_eq!(
            context.container.as_ref().unwrap().runtime.as_str(),
            "docker"
        );
    }

    #[test]
    fn vopono_metadata_merges_into_published_ports() {
        let mut context = NetworkContext::fallback(1);
        context.kind = "vopono".into();
        merge_vopono(
            &mut context,
            crate::vopono::VoponoContext {
                provider: Some("airvpn".into()),
                protocol: Some("wireguard".into()),
                server: Some("copernicus".into()),
                applications: vec![crate::vopono::VoponoApplication {
                    pid: Some(30415),
                    command: Some("transmission-gtk".into()),
                }],
                port_forwarding: Some(crate::vopono::VoponoPortForwarding {
                    port: 51234,
                    provider: Some("airvpn".into()),
                    automatic: Some(true),
                    updated: Some(1),
                }),
                open_ports: vec![43161],
                host_forwarded_ports: vec![9000],
                health: None,
            },
        );
        assert_eq!(context.published_ports, vec![9000, 43161, 51234]);
        assert_eq!(
            context.vopono.as_ref().unwrap().provider.as_deref(),
            Some("airvpn")
        );
        assert!(
            context
                .evidence
                .iter()
                .any(|item| item == "vopono lockfile")
        );
    }

    #[test]
    fn container_cgroups_are_classified() {
        assert_eq!(
            runtime_from_cgroup("/system.slice/docker-0123456789abcdef.scope"),
            Some(("docker".into(), "0123456789ab".into()))
        );
        assert_eq!(
            runtime_from_cgroup("/user.slice/libpod-abcdef0123456789.scope"),
            Some(("podman".into(), "abcdef012345".into()))
        );
        assert_eq!(
            runtime_from_cgroup("/lxc.payload.ee-arch"),
            Some(("lxc".into(), "ee-arch".into()))
        );
        assert_eq!(
            runtime_from_cgroup("/system.slice/vopono.service"),
            Some(("vopono".into(), "vopono".into()))
        );
        assert_eq!(runtime_from_cgroup("/user.slice/session-1.scope"), None);
    }

    #[test]
    fn unit_names_are_extracted_from_cgroups() {
        assert_eq!(
            unit_from_cgroup("/system.slice/docker-abc.scope"),
            Some("docker-abc.scope".into())
        );
        assert_eq!(unit_from_cgroup("/"), None);
    }
}
