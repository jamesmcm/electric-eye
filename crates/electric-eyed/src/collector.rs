use crate::{btf::Layout, format::TraceFormat, probe, wire::*};
use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfLoader, Pod};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
const PERF_FLAG_FD_CLOEXEC: u32 = 8;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
unsafe impl Pod for Record {}
unsafe impl Pod for KernelOffsets {}
unsafe impl Pod for SockOffsets {}

pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
pub fn decode(data: &[u8]) -> Option<Record> {
    if data.len() != std::mem::size_of::<Record>() {
        return None;
    }
    let record = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<Record>()) };
    (record.version == ABI_VERSION && record.kind <= NET_CLOSE && record.start_ns != 0)
        .then_some(record)
}
#[derive(Debug, Default)]
pub struct AttachReport {
    pub attached: Vec<String>,
    pub skipped: Vec<String>,
}
impl AttachReport {
    fn attach(&mut self, name: &str) {
        self.attached.push(name.into());
    }
    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped.push(format!("{name}: {reason}"));
    }
}
pub struct Collector {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
    dropped: PerCpuArray<MapData, u64>,
    _perf_links: Vec<OwnedFd>,
    batch_limit: usize,
}
impl Collector {
    pub fn load(path: &Path, config: &crate::config::Config) -> Result<(Self, AttachReport)> {
        anyhow::ensure!(
            probe::ringbuf_supported(),
            "kernel ring buffer support is required"
        );
        let mut loader = EbpfLoader::new();
        loader
            .map_max_entries("EVENTS", config.capture.ring_bytes)
            .map_max_entries("PENDING", config.capture.pending_entries)
            .map_max_entries("SOCKETS", config.capture.socket_entries)
            .map_max_entries("NET_PENDING", config.capture.network_pending_entries)
            .map_max_entries("READ_PREFIXES", config.capture.read_prefix_entries)
            .map_max_entries("IGNORE_PREFIXES", config.capture.read_prefix_entries);
        let mut bpf = loader
            .load_file(path)
            .with_context(|| format!("loading {}", path.display()))?;
        let mut report = AttachReport::default();
        let mut links = Vec::new();
        publish_kernel_offsets(&mut bpf)?;
        publish_syscalls(&mut bpf)?;
        fill_read_prefixes(&mut bpf, config)?;
        fill_ignore_prefixes(&mut bpf, config)?;
        for (program, category, event) in [
            ("electric_eye_exec", "sched", "sched_process_exec"),
            ("electric_eye_exit", "sched", "sched_process_exit"),
            ("electric_eye_sys_enter", "raw_syscalls", "sys_enter"),
            ("electric_eye_sys_exit", "raw_syscalls", "sys_exit"),
        ] {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                &mut links,
                program,
                category,
                event,
                true,
            )?;
        }
        publish_sock_offsets(&mut bpf)?;
        attach_tracepoint(
            &mut bpf,
            &mut report,
            &mut links,
            "electric_eye_sock_state",
            "sock",
            "inet_sock_set_state",
            true,
        )?;
        for (symbol, program, ret) in [
            ("wake_up_new_task", "electric_eye_fork", false),
            ("sk_destruct", "electric_eye_socket_free", false),
            ("inet_release", "electric_eye_socket_release", false),
            ("__skb_recv_udp", "electric_eye_udp_skb", true),
            ("udpv6_sendmsg", "electric_eye_udp_sent_enter", false),
            ("udpv6_recvmsg", "electric_eye_udp_recv_enter", false),
            ("udpv6_sendmsg", "electric_eye_udp_sent", true),
            ("udpv6_recvmsg", "electric_eye_udp_recv", true),
            ("tcp_sendmsg", "electric_eye_tcp_sent_enter", false),
            ("tcp_recvmsg", "electric_eye_tcp_recv_enter", false),
            ("udp_sendmsg", "electric_eye_udp_sent_enter", false),
            ("udp_recvmsg", "electric_eye_udp_recv_enter", false),
            ("tcp_sendmsg", "electric_eye_tcp_sent", true),
            ("tcp_recvmsg", "electric_eye_tcp_recv", true),
            ("udp_sendmsg", "electric_eye_udp_sent", true),
            ("udp_recvmsg", "electric_eye_udp_recv", true),
            (
                "security_path_truncate",
                "electric_eye_path_truncate",
                false,
            ),
            ("security_path_unlink", "electric_eye_path_unlink", false),
            ("security_path_rmdir", "electric_eye_path_unlink", false),
            ("security_path_rename", "electric_eye_path_rename", false),
        ] {
            // One program may attach to both unlink and rmdir.
            match attach_probe(&mut bpf, &mut links, program, symbol, ret) {
                Ok(()) => report.attach(&format!("{program}:{symbol}")),
                Err(err) => report.skip(program, &format!("{symbol}: {err:#}")),
            }
        }
        let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS missing")?)?;
        let dropped = PerCpuArray::try_from(bpf.take_map("DROPPED").context("DROPPED missing")?)?;
        Ok((
            Self {
                _bpf: bpf,
                ring,
                dropped,
                _perf_links: links,
                batch_limit: config.limits.collector_batch,
            },
            report,
        ))
    }
    pub fn drain_once<F: FnMut(Record)>(&mut self, handler: &mut F) -> Result<usize> {
        let mut count = 0;
        while count < self.batch_limit {
            let Some(item) = self.ring.next() else {
                break;
            };
            let record = decode(&item).context("invalid or incompatible BPF event ABI")?;
            handler(record);
            count += 1;
        }
        Ok(count)
    }
    pub fn loss_counts(&self) -> Vec<u64> {
        (0..DROP_COUNT)
            .map(|i| self.dropped.get(&i, 0).map(|v| v.iter().sum()).unwrap_or(0))
            .collect()
    }
}
fn field(format: &TraceFormat, name: &str) -> Result<u32> {
    format
        .offset(name)
        .map(|v| v as u32)
        .with_context(|| format!("missing tracepoint field {name}"))
}
fn publish_kernel_offsets(bpf: &mut Ebpf) -> Result<()> {
    let b = Layout::load()?;
    let m = |ty, member| b.member(ty, member);
    let enter = TraceFormat::load("raw_syscalls", "sys_enter")?;
    let exit = TraceFormat::load("raw_syscalls", "sys_exit")?;
    let namespace = std::fs::metadata("/proc/self/ns/pid")?;
    let offsets = KernelOffsets {
        skb_head: m("sk_buff", "head")?,
        skb_network: m("sk_buff", "network_header")?,
        skb_transport: m("sk_buff", "transport_header")?,
        socket_type: m("socket", "type")?,
        skc_net: m("sock_common", "skc_net")?,
        net_inum: m("net", "ns")? + m("ns_common", "inum")?,
        skc_rcv_saddr: m("sock_common", "skc_rcv_saddr")?,
        skc_v6_rcv_saddr: m("sock_common", "skc_v6_rcv_saddr")?,
        msg_name: m("msghdr", "msg_name")?,
        inode_ino: m("inode", "i_ino")?,
        inode_sb: m("inode", "i_sb")?,
        sb_dev: m("super_block", "s_dev")?,
        task_pid: m("task_struct", "pid")?,
        task_thread_pid: m("task_struct", "thread_pid")?,
        pid_level: m("pid", "level")?,
        pid_numbers: m("pid", "numbers")?,
        upid_ns: m("upid", "ns")?,
        upid_nr: m("upid", "nr")?,
        pid_ns_inum: m("pid_namespace", "ns")? + m("ns_common", "inum")?,
        task_cred: m("task_struct", "cred")?,
        cred_uid: m("cred", "uid")?,
        cred_euid: m("cred", "euid")?,
        task_exec_id: m("task_struct", "self_exec_id")?,
        task_exit_code: m("task_struct", "exit_code")?,
        task_signal: m("task_struct", "signal")?,
        signal_live: m("signal_struct", "live")?,
        mm_arg_start: m("mm_struct", "arg_start")?,
        mm_arg_end: m("mm_struct", "arg_end")?,
        task_cgroups: m("task_struct", "cgroups")?,
        css_dfl_cgrp: m("css_set", "dfl_cgrp")?,
        cgroup_kn: m("cgroup", "kn")?,
        kn_parent: m("kernfs_node", "parent").or_else(|_| m("kernfs_node", "__parent"))?,
        kn_name: m("kernfs_node", "name")?,
        task_comm: m("task_struct", "comm")?,
        task_group_leader: m("task_struct", "group_leader")?,
        task_start_boottime: m("task_struct", "start_boottime")?,
        task_real_parent: m("task_struct", "real_parent")?,
        task_tgid: m("task_struct", "tgid")?,
        task_fs: m("task_struct", "fs")?,
        task_files: m("task_struct", "files")?,
        task_mm: m("task_struct", "mm")?,
        mm_exe_file: m("mm_struct", "exe_file")?,
        fs_root: m("fs_struct", "root")?,
        fs_pwd: m("fs_struct", "pwd")?,
        files_fdt: m("files_struct", "fdt")?,
        fdt_fd: m("fdtable", "fd")?,
        fdt_max_fds: m("fdtable", "max_fds")?,
        file_path: m("file", "f_path")?,
        file_inode: m("file", "f_inode")?,
        inode_mode: m("inode", "i_mode")?,
        path_mnt: m("path", "mnt")?,
        path_dentry: m("path", "dentry")?,
        dentry_parent: m("dentry", "d_parent")?,
        dentry_name: m("dentry", "d_name")?,
        qstr_len: m("qstr", "len")?,
        qstr_name: m("qstr", "name")?,
        vfsmount_root: m("vfsmount", "mnt_root")?,
        mount_mnt: m("mount", "mnt")?,
        mount_parent: m("mount", "mnt_parent")?,
        mount_mountpoint: m("mount", "mnt_mountpoint")?,
        enter_id: field(&enter, "id")?,
        enter_args: field(&enter, "args")?,
        exit_ret: field(&exit, "ret")?,
        own_pid: std::process::id(),
        file_private_data: m("file", "private_data")?,
        socket_sk: m("socket", "sk")?,
        sock_common: m("sock", "__sk_common")?,
        skc_family: m("sock_common", "skc_family")?,
        skc_state: m("sock_common", "skc_state")?,
        skc_num: m("sock_common", "skc_num")?,
        skc_dport: m("sock_common", "skc_dport")?,
        skc_daddr: m("sock_common", "skc_daddr")?,
        skc_v6_daddr: m("sock_common", "skc_v6_daddr")?,
        own_ns_dev: namespace.dev(),
        own_ns_ino: namespace.ino(),
    };
    let mut map: HashMap<_, u32, KernelOffsets> = bpf
        .map_mut("KERNEL_OFFSETS")
        .context("KERNEL_OFFSETS missing")?
        .try_into()?;
    map.insert(0, offsets, 0)?;
    Ok(())
}
fn publish_sock_offsets(bpf: &mut Ebpf) -> Result<()> {
    let f = TraceFormat::load("sock", "inet_sock_set_state")?;
    let m = |name| field(&f, name);
    let o = SockOffsets {
        skaddr: m("skaddr")?,
        newstate: m("newstate")?,
        sport: m("sport")?,
        dport: m("dport")?,
        family: m("family")?,
        protocol: m("protocol")?,
        saddr4: m("saddr")?,
        daddr4: m("daddr")?,
        saddr6: m("saddr_v6")?,
        daddr6: m("daddr_v6")?,
    };
    let mut map: HashMap<_, u32, SockOffsets> = bpf
        .map_mut("SOCK_OFFSETS")
        .context("SOCK_OFFSETS missing")?
        .try_into()?;
    map.insert(0, o, 0)?;
    Ok(())
}
fn publish_syscalls(bpf: &mut Ebpf) -> Result<()> {
    let mut map: HashMap<_, u64, u32> = bpf
        .map_mut("SYSCALL_OPS")
        .context("SYSCALL_OPS missing")?
        .try_into()?;
    for (nr, op) in [
        (libc::SYS_open, OP_OPEN),
        (libc::SYS_creat, OP_CREAT),
        (libc::SYS_truncate, OP_TRUNCATE),
        (libc::SYS_ftruncate, OP_FTRUNCATE),
        (libc::SYS_openat, OP_OPENAT),
        (libc::SYS_openat2, OP_OPENAT2),
        (libc::SYS_write, OP_WRITE),
        (libc::SYS_writev, OP_WRITE),
        (libc::SYS_pwrite64, OP_WRITE),
        (libc::SYS_pwritev, OP_WRITE),
        (libc::SYS_pwritev2, OP_WRITE),
        (libc::SYS_sendfile, OP_SENDFILE),
        (libc::SYS_copy_file_range, OP_COPY),
        (libc::SYS_mmap, OP_MMAP),
        (libc::SYS_unlink, OP_UNLINK),
        (libc::SYS_rmdir, OP_UNLINK),
        (libc::SYS_unlinkat, OP_UNLINKAT),
        (libc::SYS_rename, OP_RENAME),
        (libc::SYS_renameat, OP_RENAMEAT),
        (libc::SYS_renameat2, OP_RENAMEAT),
        (libc::SYS_getsockopt, OP_SOERROR),
        (libc::SYS_socket, OP_SOCKET),
        (libc::SYS_bind, OP_BIND),
        (libc::SYS_connect, OP_CONNECT),
        (libc::SYS_accept, OP_ACCEPT),
        (libc::SYS_accept4, OP_ACCEPT),
    ] {
        map.insert(nr as u64, op, 0)?;
    }
    Ok(())
}
fn fill_read_prefixes(bpf: &mut Ebpf, config: &crate::config::Config) -> Result<()> {
    let mut trie: LpmTrie<_, [u8; 128], u8> = bpf
        .map_mut("READ_PREFIXES")
        .context("READ_PREFIXES missing")?
        .try_into()?;
    let mut prefixes = if config.capture.builtin_read_prefixes {
        sensitive_read_prefixes()
    } else {
        Vec::new()
    };
    prefixes.extend(config.capture.read_prefixes.clone());
    prefixes.extend(
        config
            .rules
            .sensitive_paths
            .iter()
            .map(|r| r.prefix.clone()),
    );
    prefixes.sort();
    prefixes.dedup();
    for prefix in prefixes {
        let bytes = prefix.as_bytes();
        if bytes.len() > 128 {
            log::warn!("read prefix too long: {prefix}");
            continue;
        }
        let mut data = [0u8; 128];
        data[..bytes.len()].copy_from_slice(bytes);
        trie.insert(&Key::new((bytes.len() * 8) as u32, data), 1, 0)?;
    }
    Ok(())
}

fn fill_ignore_prefixes(bpf: &mut Ebpf, config: &crate::config::Config) -> Result<()> {
    let mut trie: LpmTrie<_, [u8; 128], u8> = bpf
        .map_mut("IGNORE_PREFIXES")
        .context("IGNORE_PREFIXES missing")?
        .try_into()?;
    let mut prefixes = config.ignore_paths.clone();
    prefixes.extend(config.capture.noise_paths.clone());
    prefixes.sort();
    prefixes.dedup();
    for prefix in prefixes {
        let bytes = prefix.as_bytes();
        if bytes.len() > 128 {
            log::warn!("ignore prefix too long: {prefix}");
            continue;
        }
        let mut data = [0u8; 128];
        data[..bytes.len()].copy_from_slice(bytes);
        trie.insert(&Key::new((bytes.len() * 8) as u32, data), 1, 0)?;
    }
    Ok(())
}

/// A subset of `struct perf_event_attr` up to `config2` (the newest field we
/// use). The kernel accepts an attribute size smaller than its own struct for
/// backwards compatibility, which keeps this layout valid on older kernels.
#[repr(C)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
}

impl PerfEventAttr {
    fn tracepoint(event_id: u64) -> Self {
        Self {
            type_: PERF_TYPE_TRACEPOINT,
            size: std::mem::size_of::<Self>() as u32,
            config: event_id,
            sample_period: 0,
            sample_type: PERF_SAMPLE_RAW,
            read_format: 0,
            // disabled=1; enabled explicitly after BPF is attached.
            flags: 1,
            wakeup_events: 1,
            bp_type: 0,
            config1: 0,
            config2: 0,
        }
    }

    fn kprobe(pmu_type: u32, retprobe_bit: Option<u32>, name: &CString, offset: u64) -> Self {
        Self {
            type_: pmu_type,
            size: std::mem::size_of::<Self>() as u32,
            config: retprobe_bit.map(|bit| 1_u64 << bit).unwrap_or(0),
            sample_period: 0,
            sample_type: PERF_SAMPLE_RAW,
            read_format: 0,
            flags: 1,
            wakeup_events: 1,
            bp_type: 0,
            config1: name.as_ptr() as u64,
            config2: offset,
        }
    }
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    report: &mut AttachReport,
    perf_links: &mut Vec<OwnedFd>,
    program: &str,
    category: &str,
    event: &str,
    required: bool,
) -> Result<()> {
    let result = (|| -> Result<()> {
        let id = crate::format::event_id(category, event)
            .with_context(|| format!("tracepoint {category}/{event} unavailable"))?;
        let tp: &mut TracePoint = bpf
            .program_mut(program)
            .with_context(|| format!("program {program} missing from the object"))?
            .try_into()?;
        tp.load()?;
        let prog_fd = tp.fd()?.as_fd().as_raw_fd();
        let fds = perf_attach(prog_fd, &PerfEventAttr::tracepoint(id))
            .with_context(|| format!("failed to attach {category}/{event}"))?;
        perf_links.extend(fds);
        Ok(())
    })();
    match result {
        Ok(()) => {
            report.attach(program);
            Ok(())
        }
        Err(err) if !required => {
            report.skip(program, &format!("{err:#}"));
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn attach_probe(
    bpf: &mut Ebpf,
    perf_links: &mut Vec<OwnedFd>,
    program: &str,
    symbol: &str,
    ret: bool,
) -> Result<()> {
    let pmu_type = read_trimmed("/sys/bus/event_source/devices/kprobe/type")
        .context("kprobe PMU type unavailable")?
        .parse::<u32>()
        .context("invalid kprobe PMU type")?;
    let retprobe_bit = if ret {
        let text = read_trimmed("/sys/bus/event_source/devices/kprobe/format/retprobe")
            .context("retprobe PMU support required")?;
        Some(
            text.split_once(':')
                .context("invalid retprobe format")?
                .1
                .parse::<u32>()?,
        )
    } else {
        None
    };

    let name = CString::new(symbol).context("kprobe symbol contains a NUL byte")?;
    let kp: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from the object"))?
        .try_into()?;
    if kp.fd().is_err() {
        kp.load()?;
    }
    let prog_fd = kp.fd()?.as_fd().as_raw_fd();
    let fds = perf_attach(
        prog_fd,
        &PerfEventAttr::kprobe(pmu_type, retprobe_bit, &name, 0),
    )
    .with_context(|| format!("failed to attach kretprobe:{symbol}"))?;
    perf_links.extend(fds);
    Ok(())
}

fn read_trimmed(path: &str) -> io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn perf_attach(prog_fd: RawFd, attr: &PerfEventAttr) -> io::Result<Vec<OwnedFd>> {
    // A tracepoint's BPF program array is shared by every CPU: opening one
    // perf event enables the tracepoint system-wide and the program runs on
    // all CPUs. Attaching the same program once per CPU is rejected with
    // EEXIST by the kernel, so keep a single anchor event.
    let cpu = probe::online_cpus()?.into_iter().next().unwrap_or(0);
    let fd = perf_event_open(attr, cpu)
        .map_err(|err| io::Error::new(err.kind(), format!("cpu {cpu}: {err}")))?;
    perf_ioctl(&fd, PERF_EVENT_IOC_SET_BPF, prog_fd as libc::c_ulong)?;
    perf_ioctl(&fd, PERF_EVENT_IOC_ENABLE, 0)?;
    Ok(vec![fd])
}

fn perf_event_open(attr: &PerfEventAttr, cpu: u32) -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr as *const PerfEventAttr,
            -1_i32,
            cpu as i32,
            -1_i32,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn perf_ioctl(fd: &OwnedFd, request: libc::c_ulong, arg: libc::c_ulong) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sensitive_read_prefixes() -> Vec<String> {
    let mut prefixes = vec![
        "/etc/ssh".to_string(),
        "/etc/shadow".to_string(),
        "/etc/gshadow".to_string(),
        "/etc/sudoers".to_string(),
        "/etc/sudoers.d".to_string(),
        "/root/.ssh".to_string(),
        "/root/.gnupg".to_string(),
        "/root/.aws".to_string(),
        "/root/.kube".to_string(),
    ];

    prefixes.extend(
        crate::credentials::SYSTEM
            .iter()
            .map(|path| (*path).to_string()),
    );
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return prefixes;
    };
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let home = Path::new(fields[5]);
        if !home.is_absolute() {
            continue;
        }
        for relative in crate::credentials::HOME
            .iter()
            .map(|(path, _)| *path)
            .chain(crate::credentials::BROWSERS.iter().copied())
        {
            prefixes.push(home.join(relative).display().to_string());
        }
    }
    prefixes.sort();
    prefixes.dedup();
    prefixes
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_record_roundtrip_and_version_check() {
        let mut event = Record::ZERO;
        event.start_ns = 123;
        event.kind = WRITE;
        event.count = 17;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const Record).cast::<u8>(),
                std::mem::size_of::<Record>(),
            )
        };
        assert_eq!(decode(bytes).unwrap().count, 17);
        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
        event.version = 1;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const Record).cast::<u8>(),
                std::mem::size_of::<Record>(),
            )
        };
        assert!(decode(bytes).is_none());
    }
}
