use crate::{
    api::ProcessIdentity,
    net_context::{NetworkContext, Resolver},
    process::{ProcessRecord, key},
    wire,
};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
#[derive(Clone, Debug, Serialize)]
pub struct Contributor {
    pub process: ProcessIdentity,
    pub executable: Option<String>,
    pub comm: String,
    pub sent: u64,
    pub received: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Flow {
    pub id: String,
    pub socket_id: u64,
    pub namespace: u64,
    pub protocol: String,
    pub kind: String,
    pub role: String,
    pub direction: String,
    pub exposure: String,
    pub local: String,
    pub local_port: u16,
    pub remote: String,
    pub remote_port: u16,
    pub scope: String,
    pub state: String,
    pub network_context: NetworkContext,
    pub opened_ms: u64,
    pub last_seen_ms: u64,
    pub closed_ms: Option<u64>,
    pub duration_ms: u64,
    pub sent: u64,
    pub received: u64,
    pub owner: ProcessIdentity,
    pub application: Option<crate::grouping::Attribution>,
    pub contributors: BTreeMap<String, Contributor>,
    pub contributors_truncated: bool,
    pub errno: Option<i64>,
    pub byte_semantics: String,
    pub partial_start: bool,
}
pub struct Tracker {
    session: String,
    sequence: u64,
    pub rows: crate::cache::Recent<Flow>,
    sockets: HashMap<(u64, u64), SocketRows>,
    contributor_limit: usize,
    context: Resolver,
}
#[derive(Default)]
struct SocketRows {
    base: Option<String>,
    peers: HashMap<String, String>,
}
impl Default for Tracker {
    fn default() -> Self {
        Self::with_limits(&crate::config::Limits::default())
    }
}
impl Tracker {
    pub fn with_limits(limits: &crate::config::Limits) -> Self {
        Self {
            session: std::fs::read_to_string("/proc/sys/kernel/random/uuid")
                .unwrap_or_else(|_| format!("{}-{}", std::process::id(), crate::api::now_ms()))
                .trim()
                .into(),
            sequence: 0,
            rows: crate::cache::Recent::new(limits.flow_entries),
            sockets: HashMap::new(),
            contributor_limit: limits.flow_contributors,
            context: Resolver::default(),
        }
    }
}
fn ip(family: u32, addr: [u8; 16]) -> std::net::IpAddr {
    if family == 2 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr))
    }
}
fn endpoint(family: u32, addr: [u8; 16], port: u32) -> String {
    format!(
        "{}",
        std::net::SocketAddr::new(ip(family, addr), port as u16)
    )
}
fn scope(addr: std::net::IpAddr) -> String {
    crate::net_context::address_scope(addr).into()
}

fn direction_for(kind: u32) -> &'static str {
    match kind {
        wire::LISTEN | wire::ACCEPT => "inbound",
        wire::CONNECT => "outbound",
        _ => "unknown",
    }
}

fn is_tracker_port(port: u16) -> bool {
    matches!(port, 451 | 1337 | 2710 | 6969)
}

fn role_for(flow: &Flow) -> String {
    if flow.state == "listening" {
        return "listener".into();
    }
    if flow.local_port == 53 || flow.remote_port == 53 {
        return "dns".into();
    }
    if flow.local_port == 6771 || flow.remote_port == 6771 {
        return "lpd".into();
    }
    if flow.kind == "udp_peer" {
        return "udp_peer".into();
    }
    if flow.direction == "outbound" && flow.protocol == "UDP" && is_tracker_port(flow.remote_port) {
        return "tracker".into();
    }
    if flow.state == "failed" {
        return "failed".into();
    }
    match flow.direction.as_str() {
        "inbound" => "inbound".into(),
        "outbound" => "outbound".into(),
        _ => "socket".into(),
    }
}

fn exposure_for(flow: &Flow) -> String {
    if !matches!(flow.direction.as_str(), "inbound") {
        return "n/a".into();
    }
    if flow
        .network_context
        .published_ports
        .contains(&flow.local_port)
        || flow
            .network_context
            .published_container_ports
            .contains(&flow.local_port)
    {
        return "published".into();
    }
    let Some(address) = flow
        .local
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|endpoint| endpoint.ip())
    else {
        return "unknown".into();
    };
    match address {
        std::net::IpAddr::V4(address) if address.is_loopback() => "loopback".into(),
        std::net::IpAddr::V6(address) if address.is_loopback() => "loopback".into(),
        std::net::IpAddr::V4(address) if address.is_unspecified() => "all_interfaces".into(),
        std::net::IpAddr::V6(address) if address.is_unspecified() => "all_interfaces".into(),
        std::net::IpAddr::V4(address) if address.is_private() || address.is_link_local() => {
            "local_network".into()
        }
        std::net::IpAddr::V6(address)
            if address.is_unique_local() || address.is_unicast_link_local() =>
        {
            "local_network".into()
        }
        _ => "internet".into(),
    }
}

impl Tracker {
    pub fn observe(
        &mut self,
        r: &wire::Record,
        boot: &str,
        ts: u64,
        p: Option<&ProcessRecord>,
    ) -> Vec<Flow> {
        if r.socket_id == 0 {
            return Vec::new();
        }
        if r.kind == wire::NET_CLOSE || r.kind == wire::NET_STATE && r.state == 7 {
            let mut changed = Vec::new();
            let ids: Vec<_> = self
                .sockets
                .get(&(r.netns, r.socket_id))
                .map(|s| s.peers.values().cloned().collect())
                .unwrap_or_default();
            for id in ids {
                if let Some(f) = self.rows.get_mut(&id)
                    && f.closed_ms.is_none()
                {
                    f.closed_ms = Some(ts);
                    f.duration_ms = ts.saturating_sub(f.opened_ms);
                    f.last_seen_ms = ts;
                    f.state = if f.protocol == "TCP" && f.state == "connecting" {
                        "failed"
                    } else {
                        "closed"
                    }
                    .into();
                    changed.push(f.clone());
                }
                if r.kind == wire::NET_CLOSE {
                    self.rows.remove(&id);
                }
            }
            if r.kind == wire::NET_CLOSE {
                self.sockets.remove(&(r.netns, r.socket_id));
            }
            return changed;
        }
        let remote = endpoint(r.family, r.addr, r.remote_port);
        let local = endpoint(r.family, r.local_addr, r.local_port);
        let peer = r.protocol == 17 && matches!(r.kind, wire::SENT | wire::RECEIVED);
        let peer_key = if peer { remote.as_str() } else { "socket" };
        let id = if let Some(id) = self
            .sockets
            .get(&(r.netns, r.socket_id))
            .and_then(|s| s.peers.get(peer_key))
        {
            id.clone()
        } else {
            self.sequence = self.sequence.saturating_add(1);
            format!(
                "{}:{}:{}:{}",
                self.session, r.netns, r.socket_id, self.sequence
            )
        };
        let identity = ProcessIdentity {
            pid: r.pid,
            start_ns: r.start_ns,
            boot_id: boot.into(),
        };
        let network_context = self.context.resolve(r.netns, p);
        let base = self
            .sockets
            .get(&(r.netns, r.socket_id))
            .and_then(|s| s.base.as_ref())
            .and_then(|id| self.rows.get(id))
            .map(|f| (f.owner.clone(), f.application.clone(), f.partial_start));
        let socket = self.sockets.entry((r.netns, r.socket_id)).or_default();
        socket.peers.insert(peer_key.into(), id.clone());
        if !peer {
            socket.base = Some(id.clone());
        }
        let mut f = self.rows.get(&id).cloned().unwrap_or_else(|| Flow {
            id: id.clone(),
            socket_id: r.socket_id,
            namespace: r.netns,
            protocol: if r.protocol == 17 { "UDP" } else { "TCP" }.into(),
            kind: if peer { "udp_peer" } else { "socket" }.into(),
            role: "socket".into(),
            direction: direction_for(r.kind).into(),
            exposure: "n/a".into(),
            local: local.clone(),
            local_port: r.local_port as u16,
            remote: remote.clone(),
            remote_port: r.remote_port as u16,
            scope: scope(ip(r.family, r.addr)),
            state: "created".into(),
            network_context: network_context.clone(),
            opened_ms: ts,
            last_seen_ms: ts,
            closed_ms: None,
            duration_ms: 0,
            sent: 0,
            received: 0,
            owner: base
                .as_ref()
                .map(|b| b.0.clone())
                .unwrap_or_else(|| identity.clone()),
            application: base
                .as_ref()
                .and_then(|b| b.1.clone())
                .or_else(|| p.and_then(|p| p.application.clone())),
            contributors: BTreeMap::new(),
            contributors_truncated: false,
            errno: None,
            partial_start: base
                .as_ref()
                .map(|b| b.2)
                .unwrap_or(!matches!(r.kind, wire::SOCKET | wire::ACCEPT)),
            byte_semantics:
                "successful application I/O; excludes retransmissions and packet overhead".into(),
        });
        f.last_seen_ms = ts;
        f.duration_ms = ts.saturating_sub(f.opened_ms);
        if r.local_port != 0 {
            f.local = local;
            f.local_port = r.local_port as u16;
        }
        if r.remote_port != 0 {
            f.remote = remote;
            f.remote_port = r.remote_port as u16;
            f.scope = scope(ip(r.family, r.addr));
        }
        if f.application.is_none() {
            f.application = p.and_then(|p| p.application.clone());
        }
        if f.network_context.kind == "namespace" && network_context.kind != "namespace" {
            f.network_context = network_context.clone();
        }
        if f.direction == "unknown" && matches!(r.kind, wire::LISTEN | wire::ACCEPT | wire::CONNECT)
        {
            f.direction = direction_for(r.kind).into();
        }
        match r.kind {
            wire::CONNECT => {
                f.state = "connecting".into();
                f.closed_ms = None;
                f.errno = None;
            }
            wire::LISTEN => f.state = "listening".into(),
            wire::ACCEPT => f.state = "established".into(),
            wire::BIND => {
                if r.result >= 0 {
                    f.state = "bound".into();
                    f.errno = None;
                } else {
                    f.state = "bind_failed".into();
                    f.errno = Some(-r.result);
                }
            }
            wire::NET_RESULT => {
                // SO_ERROR is a consumable pending error, not a connect return.
                // A zero value must not resurrect failed or unconnected sockets.
                if r.flags == wire::FLAG_SO_ERROR && r.result == 0 {
                    if r.state == 1 && f.state == "connecting" {
                        f.state = if r.protocol == 6 {
                            "established"
                        } else {
                            "connected_udp"
                        }
                        .into();
                        f.closed_ms = None;
                        f.errno = None;
                    }
                } else if r.result == 0 {
                    f.errno = None;
                    f.closed_ms = None;
                    f.state = if r.protocol == 6 {
                        "established"
                    } else {
                        "connected_udp"
                    }
                    .into();
                } else if matches!(r.result, -115 | -114 | -4) {
                    f.state = "connecting".into();
                } else {
                    f.state = "failed".into();
                    f.errno = Some(-r.result);
                    f.closed_ms = Some(ts);
                }
            }
            wire::NET_STATE if r.state == 1 => f.state = "established".into(),
            wire::SENT | wire::RECEIVED => {
                let contributor_key = key(&identity);
                if f.contributors.len() < self.contributor_limit
                    || f.contributors.contains_key(&contributor_key)
                {
                    let c = f
                        .contributors
                        .entry(contributor_key)
                        .or_insert_with(|| Contributor {
                            process: identity.clone(),
                            executable: p.and_then(|p| p.executable.clone()),
                            comm: crate::collector::cstr(&r.comm),
                            sent: 0,
                            received: 0,
                        });
                    if r.kind == wire::SENT {
                        c.sent = c.sent.saturating_add(r.count);
                    } else {
                        c.received = c.received.saturating_add(r.count);
                    }
                } else {
                    f.contributors_truncated = true;
                }
                if r.kind == wire::SENT {
                    f.sent = f.sent.saturating_add(r.count);
                } else {
                    f.received = f.received.saturating_add(r.count);
                }
                if peer {
                    f.state = "peer_activity".into();
                } else if f.state == "created" {
                    f.state = "observed_io".into();
                }
            }
            _ => {}
        }
        f.role = role_for(&f);
        f.exposure = exposure_for(&f);
        if let Some(old) = self.rows.insert_evicting(id, ts, f.clone()) {
            let key = (old.namespace, old.socket_id);
            if let Some(socket) = self.sockets.get_mut(&key) {
                let peer = if old.kind == "udp_peer" {
                    old.remote.as_str()
                } else {
                    "socket"
                };
                socket.peers.remove(peer);
                if socket.base.as_ref() == Some(&old.id) {
                    socket.base = None;
                }
                if socket.peers.is_empty() {
                    self.sockets.remove(&key);
                }
            }
        }
        vec![f]
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evicted_live_flow_starts_a_new_segment_instead_of_overwriting_byte_totals() {
        let mut tracker = Tracker {
            rows: crate::cache::Recent::new(1),
            ..Tracker::default()
        };
        let mut r = wire::Record::ZERO;
        r.protocol = 17;
        r.family = 2;
        r.kind = wire::SENT;
        r.count = 5;
        r.socket_id = 1;
        let first = tracker.observe(&r, "boot", 1, None).remove(0);
        r.socket_id = 2;
        tracker.observe(&r, "boot", 2, None);
        r.socket_id = 1;
        let resumed = tracker.observe(&r, "boot", 3, None).remove(0);
        assert_ne!(first.id, resumed.id);
        assert!(resumed.partial_start);
        assert_eq!(first.sent + resumed.sent, 10);
    }
    #[test]
    fn socket_churn_reclaims_flow_and_socket_state() {
        let mut tracker = Tracker::default();
        let mut r = wire::Record::ZERO;
        r.protocol = 17;
        r.family = 2;
        r.pid = 1;
        r.start_ns = 1;
        for id in 1..1000 {
            r.socket_id = id;
            r.kind = wire::SENT;
            r.count = 1;
            tracker.observe(&r, "boot", id, None);
            r.kind = wire::NET_CLOSE;
            tracker.observe(&r, "boot", id + 1, None);
        }
        assert_eq!(tracker.rows.len(), 0);
        assert!(tracker.sockets.is_empty());
        assert_eq!(scope("::ffff:127.0.0.1".parse().unwrap()), "localhost");
        assert_eq!(
            scope("100.100.100.100".parse().unwrap()),
            "tailscale-magicdns"
        );
        assert_eq!(scope("100.100.100.101".parse().unwrap()), "tailscale");
        assert_eq!(scope("fd7a:115c:a1e0::1".parse().unwrap()), "tailscale");
        assert_eq!(
            scope("fd7a:115c:a1e0::53".parse().unwrap()),
            "tailscale-magicdns"
        );
    }
    #[test]
    fn flows_expose_roles_and_published_exposure() {
        let mut tracker = Tracker::default();
        let mut r = wire::Record::ZERO;
        r.socket_id = 11;
        r.netns = 9;
        r.protocol = 6;
        r.family = 2;
        r.pid = 1;
        r.start_ns = 1;
        r.kind = wire::LISTEN;
        r.local_port = 43161;
        r.remote_port = 0;
        let mut flow = tracker.observe(&r, "boot", 1, None).remove(0);
        assert_eq!(flow.role, "listener");
        assert_eq!(flow.direction, "inbound");
        assert_eq!(flow.exposure, "all_interfaces");
        flow.network_context.published_ports.push(43161);
        flow.local = "0.0.0.0:43161".into();
        assert_eq!(exposure_for(&flow), "published");
        flow.local_port = 80;
        flow.network_context.published_ports.clear();
        flow.network_context.published_container_ports.push(80);
        assert_eq!(exposure_for(&flow), "published");

        flow.kind = "udp_peer".into();
        flow.protocol = "UDP".into();
        flow.state = "peer_activity".into();
        assert_eq!(role_for(&flow), "udp_peer");
        flow.kind = "socket".into();
        flow.direction = "outbound".into();
        flow.remote_port = 6969;
        assert_eq!(role_for(&flow), "tracker");
    }

    #[test]
    fn preserves_shared_socket_contributors_and_closes_udp_peers() {
        let mut t = Tracker::default();
        let mut r = wire::Record::ZERO;
        r.socket_id = 7;
        r.netns = 9;
        r.protocol = 17;
        r.family = 2;
        r.pid = 1;
        r.start_ns = 1;
        r.remote_port = 53;
        r.addr[0] = 127;
        r.addr[3] = 1;
        r.kind = wire::SENT;
        r.count = 5;
        t.observe(&r, "boot", 1, None);
        r.pid = 2;
        r.start_ns = 2;
        t.observe(&r, "boot", 2, None);
        let f = t.rows.values().next().unwrap();
        assert_eq!(f.sent, 10);
        assert_eq!(f.contributors.len(), 2);
        r.kind = wire::NET_CLOSE;
        let changed = t.observe(&r, "boot", 3, None);
        assert_eq!(changed[0].state, "closed");
        assert_eq!(changed[0].duration_ms, 2);
    }
}

#[cfg(test)]
mod socket_error_regressions {
    use super::*;
    #[test]
    fn reading_a_cleared_error_cannot_resurrect_a_refused_or_unconnected_socket() {
        let mut t = Tracker::default();
        let mut r = wire::Record::ZERO;
        r.socket_id = 1;
        r.family = 2;
        r.protocol = 6;
        r.pid = 1;
        r.start_ns = 1;
        r.kind = wire::NET_RESULT;
        r.result = -111;
        assert_eq!(t.observe(&r, "boot", 1, None)[0].state, "failed");
        r.flags = wire::FLAG_SO_ERROR;
        r.result = 0;
        r.state = 7;
        let failed = t.observe(&r, "boot", 2, None).remove(0);
        assert_eq!(failed.state, "failed");
        assert_eq!(failed.errno, Some(111));
        assert_eq!(failed.closed_ms, Some(1));
        r.socket_id = 2;
        r.kind = wire::SOCKET;
        r.flags = 0;
        t.observe(&r, "boot", 3, None);
        r.kind = wire::NET_RESULT;
        r.flags = wire::FLAG_SO_ERROR;
        assert_eq!(t.observe(&r, "boot", 4, None)[0].state, "created");
        r.kind = wire::CONNECT;
        r.flags = 0;
        t.observe(&r, "boot", 5, None);
        r.kind = wire::NET_RESULT;
        r.flags = wire::FLAG_SO_ERROR;
        assert_eq!(t.observe(&r, "boot", 6, None)[0].state, "connecting");
        r.state = 1;
        assert_eq!(t.observe(&r, "boot", 7, None)[0].state, "established");
    }
}
