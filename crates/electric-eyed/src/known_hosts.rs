//! Read-only OpenSSH known_hosts support.
//!
//! An SSH command whose destination is explicitly present in the user's or
//! system known_hosts is a normal, user-approved connection. We use that as a
//! default exception for SSH credential reads and network alerts.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
enum Entry {
    Pattern(String),
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

#[derive(Debug, Default)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

impl KnownHosts {
    pub fn load(home: Option<&Path>) -> Self {
        let mut hosts = Self::default();
        if let Some(home) = home {
            hosts.read(&home.join(".ssh/known_hosts"));
        }
        hosts.read(Path::new("/etc/ssh/ssh_known_hosts"));
        hosts.read(Path::new("/etc/ssh/ssh_known_hosts2"));
        hosts
    }

    fn read(&mut self, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() || line.starts_with('@') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let Some(hosts) = fields.next() else {
                continue;
            };
            if fields.next().is_none() {
                continue;
            }
            for host in hosts.split(',') {
                if host.is_empty() || host.starts_with('!') {
                    continue;
                }
                if let Some(entry) = parse_entry(host) {
                    self.entries.push(entry);
                }
            }
        }
    }

    pub fn is_known(&self, host: &str, port: u16) -> bool {
        let host = normalize_host(host);
        if host.is_empty() {
            return false;
        }
        self.entries
            .iter()
            .any(|entry| entry_matches(entry, &host, port))
    }
}

fn parse_entry(pattern: &str) -> Option<Entry> {
    if let Some(rest) = pattern.strip_prefix("|1|") {
        let (salt, hash) = rest.split_once('|')?;
        return Some(Entry::Hashed {
            salt: STANDARD.decode(salt).ok()?,
            hash: STANDARD.decode(hash).ok()?,
        });
    }
    Some(Entry::Pattern(pattern.to_string()))
}

fn entry_matches(entry: &Entry, host: &str, port: u16) -> bool {
    match entry {
        Entry::Pattern(pattern) => {
            let (pattern_host, pattern_port) = split_pattern_host(pattern);
            (pattern_port == 0 || pattern_port == port)
                && wildcard_match(&pattern_host.to_ascii_lowercase(), host)
        }
        Entry::Hashed { salt, hash } => {
            let mut candidates = vec![host.to_string()];
            if port != 22 {
                candidates.push(format!("[{host}]:{port}"));
            }
            candidates.iter().any(|candidate| {
                let Ok(mut mac) = HmacSha1::new_from_slice(salt) else {
                    return false;
                };
                mac.update(candidate.as_bytes());
                mac.verify_slice(hash).is_ok()
            })
        }
    }
}

fn split_pattern_host(pattern: &str) -> (String, u16) {
    if let Some(rest) = pattern.strip_prefix('[')
        && let Some(end) = rest.find("]:")
    {
        let host = rest[..end].to_string();
        let port = rest[end + 2..].parse().unwrap_or(0);
        return (host, port);
    }
    if let Some((host, port)) = pattern.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port.parse()
    {
        return (host.to_string(), port);
    }
    (pattern.to_string(), 0)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let (mut star, mut matched) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            matched = t;
            p += 1;
        } else if let Some(index) = star {
            p = index + 1;
            matched += 1;
            t = matched;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    let host = host.rsplit_once('@').map(|(_, host)| host).unwrap_or(host);
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.split_once(']').map(|(host, _)| host).unwrap_or(host);
    host.to_ascii_lowercase()
}

/// Find the SSH destination from a command line, ignoring option arguments.
pub fn destination(argv: &[String]) -> Option<(String, u16)> {
    let mut port = 22;
    let mut index = 1;
    let mut host = None;
    while index < argv.len() {
        let argument = &argv[index];
        if argument == "--" {
            host = argv.get(index + 1).cloned();
            break;
        }
        if argument == "-p"
            && let Some(value) = argv.get(index + 1)
        {
            port = value.parse().unwrap_or(port);
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix("-p")
            && !value.is_empty()
        {
            port = value.parse().unwrap_or(port);
            index += 1;
            continue;
        }
        if option_takes_value(argument) {
            index += 2;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        host = Some(argument.clone());
        break;
    }
    let host = host?;
    let (host, explicit_port) = split_host_port(&host);
    Some((normalize_host(&host), explicit_port.unwrap_or(port)))
}

fn option_takes_value(argument: &str) -> bool {
    matches!(
        argument,
        "-B" | "-b"
            | "-c"
            | "-D"
            | "-E"
            | "-e"
            | "-F"
            | "-I"
            | "-i"
            | "-J"
            | "-L"
            | "-l"
            | "-m"
            | "-O"
            | "-o"
            | "-Q"
            | "-R"
            | "-S"
            | "-W"
            | "-w"
    )
}

fn split_host_port(host: &str) -> (String, Option<u16>) {
    if let Some(rest) = host.strip_prefix('[')
        && let Some(end) = rest.find("]:")
    {
        return (rest[..end].to_string(), rest[end + 2..].parse().ok());
    }
    if let Some((host, port)) = host.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port.parse()
    {
        return (host.to_string(), Some(port));
    }
    (host.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_wildcard_and_port_patterns_match() {
        let hosts = KnownHosts {
            entries: vec![
                Entry::Pattern("github.com".into()),
                Entry::Pattern("*.gitlab.com".into()),
                Entry::Pattern("[alt.example.com]:2222".into()),
            ],
        };
        assert!(hosts.is_known("github.com", 22));
        assert!(hosts.is_known("ssh.gitlab.com", 22));
        assert!(hosts.is_known("alt.example.com", 2222));
        assert!(!hosts.is_known("alt.example.com", 22));
        assert!(!hosts.is_known("evil.example.com", 22));
    }

    #[test]
    fn hashed_known_hosts_entries_match() {
        let salt = b"test-salt";
        let mut mac = HmacSha1::new_from_slice(salt).unwrap();
        mac.update(b"github.com");
        let hash = mac.finalize().into_bytes();
        let line = format!(
            "|1|{}|{} ssh-ed25519 AAAA",
            STANDARD.encode(salt),
            STANDARD.encode(hash)
        );
        let mut hosts = KnownHosts::default();
        hosts.read_text_for_test(&line);
        assert!(hosts.is_known("github.com", 22));
        assert!(!hosts.is_known("gitlab.com", 22));
    }

    impl KnownHosts {
        fn read_text_for_test(&mut self, text: &str) {
            for line in text.lines() {
                let mut fields = line.split_whitespace();
                let Some(hosts) = fields.next() else {
                    continue;
                };
                for host in hosts.split(',') {
                    if let Some(entry) = parse_entry(host) {
                        self.entries.push(entry);
                    }
                }
            }
        }
    }

    #[test]
    fn extracts_ssh_destination_from_options_and_user_at_host() {
        let argv = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-p",
            "2222",
            "git@gitlab.com",
            "git-upload-pack",
            "repo.git",
        ]
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
        assert_eq!(destination(&argv), Some(("gitlab.com".into(), 2222)));
        let argv = ["ssh", "user@example.com"].map(str::to_string).to_vec();
        assert_eq!(destination(&argv), Some(("example.com".into(), 22)));
    }
}
