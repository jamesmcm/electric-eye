const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStat {
    pub ppid: u32,
    pub start_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEndpoint {
    pub family: u32,
    pub local_addr: [u8; 16],
    pub local_port: u16,
    pub remote_addr: [u8; 16],
    pub remote_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcNetTcp {
    family: u32,
    local_addr: [u8; 16],
    local_port: u16,
    remote_addr: [u8; 16],
    remote_port: u16,
    state: String,
    inode: u64,
}

pub fn process_stat(pid: u32) -> Option<ProcessStat> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat(&raw)
}

pub fn parse_stat(raw: &str) -> Option<ProcessStat> {
    let after_comm = raw.rsplit_once(") ")?;
    let fields = after_comm.1.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 20 {
        return None;
    }
    Some(ProcessStat {
        ppid: fields[1].parse().ok()?,
        start_ticks: fields[19].parse().ok()?,
    })
}

fn socket_inode(pid: u32, fd: u32) -> Option<u64> {
    let target = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let text = target.to_string_lossy();
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

/// Resolves the accepted fd using the accepting process's network namespace.
/// This is what makes ACCEPT attribution exact instead of guessing from the
/// socket-state tracepoint.
pub fn accepted_socket(pid: u32, fd: u32) -> Option<SocketEndpoint> {
    let inode = socket_inode(pid, fd)?;
    for (family, file) in [(AF_INET, "tcp"), (AF_INET6, "tcp6")] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) else {
            continue;
        };
        for socket in parse_proc_net_tcp(&text, family) {
            if socket.inode == inode && socket.state == "01" {
                return Some(SocketEndpoint {
                    family,
                    local_addr: socket.local_addr,
                    local_port: socket.local_port,
                    remote_addr: socket.remote_addr,
                    remote_port: socket.remote_port,
                });
            }
        }
    }
    None
}

/// Resolves the local port of a listening fd. Used to enrich ACCEPT events
/// captured at accept() exit, where the accepted socket may already be gone.
pub fn listener_port(pid: u32, fd: u32) -> Option<u16> {
    let inode = socket_inode(pid, fd)?;
    for (family, file) in [(AF_INET, "tcp"), (AF_INET6, "tcp6")] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) else {
            continue;
        };
        for socket in parse_proc_net_tcp(&text, family) {
            if socket.inode == inode && socket.state == "0A" {
                return Some(socket.local_port);
            }
        }
    }
    None
}

fn parse_proc_net_tcp(text: &str, family: u32) -> Vec<ProcNetTcp> {
    let mut sockets = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((local_addr, local_port)) = parse_proc_address(fields[1], family) else {
            continue;
        };
        let Some((remote_addr, remote_port)) = parse_proc_address(fields[2], family) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        sockets.push(ProcNetTcp {
            family,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state: fields[3].to_string(),
            inode,
        });
    }
    sockets
}

fn parse_proc_address(value: &str, family: u32) -> Option<([u8; 16], u16)> {
    let (addr_hex, port_hex) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let mut addr = [0_u8; 16];
    match family {
        AF_INET => {
            let raw = u32::from_str_radix(addr_hex, 16).ok()?.to_le_bytes();
            addr[..4].copy_from_slice(&raw);
        }
        AF_INET6 => {
            if addr_hex.len() != 32 {
                return None;
            }
            for (index, chunk) in addr_hex.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                addr[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        _ => return None,
    }
    Some((addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_parens_in_comm() {
        let raw = "123 (chrome:renderer) S 456 123 123 0 -1 4194560 ".to_owned()
            + &"0 ".repeat(12)
            + "987654 0 0 0 0 0 0";
        let stat = parse_stat(&raw).expect("well-formed stat line must parse");
        assert_eq!(stat.ppid, 456);
        assert_eq!(stat.start_ticks, 987654);
    }

    #[test]
    fn rejects_malformed_stat() {
        assert!(parse_stat("garbage").is_none());
        assert!(parse_stat("").is_none());
        let short = "12 (sh) S 1".to_string();
        assert!(parse_stat(&short).is_none());
    }

    #[test]
    fn parses_ipv4_proc_address() {
        let (addr, port) = parse_proc_address("0100007F:1F90", AF_INET).unwrap();
        assert_eq!(&addr[..4], &[127, 0, 0, 1]);
        assert_eq!(port, 8080);
    }

    #[test]
    fn parses_ipv6_proc_address() {
        let (addr, port) =
            parse_proc_address("00000000000000000000000001000000:14EB", AF_INET6).unwrap();
        assert_eq!(addr, std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(port, 5355);
    }

    #[test]
    fn parses_proc_net_tcp_rows() {
        let fixture = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
  0: 0100007F:99E9 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 2641095 1 00000000fc1812c4 100 0 0 10 0\n\
  1: 0100007F:1F90 0200007F:3039 01 00000000:00000000 00:00000000 00000000  1000        0 290167 1 00000000da8fc931 100 0 0 10 0\n";
        let rows = parse_proc_net_tcp(fixture, AF_INET);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_port, 0x99E9);
        assert_eq!(rows[0].state, "0A");
        assert_eq!(rows[0].inode, 2641095);
        assert_eq!(rows[1].remote_port, 0x3039);
        assert_eq!(rows[1].state, "01");
    }
}
