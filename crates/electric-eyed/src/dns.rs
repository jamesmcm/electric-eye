use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{Receiver, Sender, channel};

use electric_eye_core::event::{AF_INET, AF_INET6};

const MAX_PENDING: usize = 256;

pub struct DnsCache {
    cache: HashMap<IpAddr, String>,
    pending: HashSet<IpAddr>,
    tx: Sender<(IpAddr, Option<String>)>,
    rx: Receiver<(IpAddr, Option<String>)>,
}

impl DnsCache {
    pub fn new() -> Self {
        let mut cache = HashMap::new();
        if let Ok(text) = std::fs::read_to_string("/etc/hosts") {
            parse_hosts(&text, &mut cache);
        }
        let (tx, rx) = channel();
        Self {
            cache,
            pending: HashSet::new(),
            tx,
            rx,
        }
    }

    pub fn poll(&mut self) {
        while let Ok((ip, name)) = self.rx.try_recv() {
            self.pending.remove(&ip);
            if let Some(name) = name {
                self.cache.insert(ip, name);
            }
        }
    }

    pub fn lookup(&mut self, ip: IpAddr) -> Option<String> {
        if let Some(name) = self.cache.get(&ip) {
            return Some(name.clone());
        }
        if ip.is_unspecified() {
            return None;
        }
        if self.pending.len() < MAX_PENDING && self.pending.insert(ip) {
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                let name = dns_lookup::lookup_addr(&ip)
                    .ok()
                    .filter(|name| !name.is_empty() && name != &ip.to_string());
                let _ = tx.send((ip, name));
            });
        }
        None
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ip_from_addr(family: u32, addr: [u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            addr[0], addr[1], addr[2], addr[3],
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(addr))),
        _ => None,
    }
}

fn parse_hosts(text: &str, cache: &mut HashMap<IpAddr, String>) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok()) else {
            continue;
        };
        if let Some(name) = fields.next()
            && !cache.contains_key(&ip)
        {
            cache.insert(ip, name.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hosts_entries() {
        let mut cache = HashMap::new();
        parse_hosts(
            "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 nas.local nas # comment\n",
            &mut cache,
        );
        assert_eq!(
            cache.get(&"127.0.0.1".parse().unwrap()).map(String::as_str),
            Some("localhost")
        );
        assert_eq!(
            cache.get(&"10.0.0.5".parse().unwrap()).map(String::as_str),
            Some("nas.local")
        );
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn converts_network_addresses() {
        assert_eq!(
            ip_from_addr(AF_INET, [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Some("127.0.0.1".parse().unwrap())
        );
        let mut v6 = [0_u8; 16];
        v6[15] = 1;
        assert_eq!(ip_from_addr(AF_INET6, v6), Some("::1".parse().unwrap()));
    }
}
