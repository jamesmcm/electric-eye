use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, Pod};

use crate::format::TraceFormat;
use crate::probe;

pub const EVENT_MAP: &str = "EVENTS";
pub const PROGRAM_EXEC: &str = "electric_eye_exec";
pub const PROGRAM_EXIT: &str = "electric_eye_exit";

const RAW_EXEC_LEN: usize = 32;
const RAW_NET_LEN: usize = 56;
const RAW_PATH_LEN: usize = 548;
const RAW_RENAME_LEN: usize = 1056;
const RAW_WRITE_LEN: usize = 40;
const RAW_ACCEPT_LEN: usize = 60;
const RAW_FD_LEN: usize = 36;

const UNRESOLVED_OFFSET: u32 = u32::MAX;

pub const KIND_EXEC: u32 = 0;
pub const KIND_CONNECT: u32 = 1;
pub const KIND_LISTEN: u32 = 2;
pub const KIND_FILE_OPEN: u32 = 3;
pub const KIND_FILE_UNLINK: u32 = 4;
pub const KIND_FILE_RENAME: u32 = 5;
pub const KIND_EXIT: u32 = 6;
pub const KIND_ACCEPT: u32 = 7;
pub const KIND_FILE_WRITE: u32 = 8;
pub const KIND_FD_DUP: u32 = 9;
pub const KIND_FD_CLOSE: u32 = 10;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
const PERF_FLAG_FD_CLOEXEC: u32 = 8;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SockOffsets {
    pub oldstate: u32,
    pub newstate: u32,
    pub sport: u32,
    pub dport: u32,
    pub family: u32,
    pub protocol: u32,
    pub saddr4: u32,
    pub daddr4: u32,
    pub saddr6: u32,
    pub daddr6: u32,
}

unsafe impl Pod for SockOffsets {}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SyscallOffsets {
    pub openat_filename: u32,
    pub openat_flags: u32,
    pub openat_ret: u32,
    pub openat2_filename: u32,
    pub openat2_how: u32,
    pub openat2_ret: u32,
    pub open_filename: u32,
    pub open_flags: u32,
    pub open_ret: u32,
    pub unlinkat_pathname: u32,
    pub unlink_pathname: u32,
    pub rmdir_pathname: u32,
    pub rename_oldname: u32,
    pub rename_newname: u32,
    pub renameat_oldname: u32,
    pub renameat_newname: u32,
    pub renameat2_oldname: u32,
    pub renameat2_newname: u32,
    pub write_fd: u32,
    pub write_count: u32,
    pub accept_ret: u32,
    pub accept4_ret: u32,
    pub accept_fd: u32,
    pub accept_sockaddr: u32,
    pub accept_addrlen: u32,
    pub accept4_fd: u32,
    pub accept4_sockaddr: u32,
    pub accept4_addrlen: u32,
    pub dup2_oldfd: u32,
    pub dup2_newfd: u32,
    pub dup3_oldfd: u32,
    pub dup3_newfd: u32,
    pub close_fd: u32,
}

unsafe impl Pod for SyscallOffsets {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetTotals {
    pub sent: u64,
    pub recv: u64,
}

unsafe impl Pod for NetTotals {}

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

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

impl RawExecEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNetEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub family: u32,
    pub sport: u32,
    pub dport: u32,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
}

impl RawNetEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPathEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub fd: u32,
    pub comm: [u8; 16],
    pub path: [u8; 512],
}

impl RawPathEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }

    pub fn path_str(&self) -> String {
        cstr(&self.path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawWriteEvent {
    pub pid: u32,
    pub uid: u32,
    pub fd: u32,
    pub count: u64,
    pub comm: [u8; 16],
}

impl RawWriteEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAcceptEvent {
    pub pid: u32,
    pub uid: u32,
    pub fd: u32,
    pub listen_fd: u32,
    pub family: u32,
    pub port: u32,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
}

impl RawAcceptEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFdEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub oldfd: u32,
    pub newfd: u32,
    pub comm: [u8; 16],
}

impl RawFdEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRenameEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub old_path: [u8; 512],
    pub new_path: [u8; 512],
}

impl RawRenameEvent {
    pub fn comm_str(&self) -> String {
        cstr(&self.comm)
    }

    pub fn old_path_str(&self) -> String {
        cstr(&self.old_path)
    }

    pub fn new_path_str(&self) -> String {
        cstr(&self.new_path)
    }
}

#[derive(Debug, Clone)]
pub enum RawEvent {
    Exec(RawExecEvent),
    Exit(RawExecEvent),
    Connect(RawNetEvent),
    Listen(RawNetEvent),
    Accept(RawAcceptEvent),
    FdDup(RawFdEvent),
    FdClose(RawFdEvent),
    FileOpen(RawPathEvent),
    FileWrite(RawWriteEvent),
    FileUnlink(RawPathEvent),
    FileRename(Box<RawRenameEvent>),
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn read_array<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at + N)?.try_into().ok()
}

pub fn decode(data: &[u8]) -> Option<RawEvent> {
    let kind = read_u32(data, 0)?;
    match kind {
        KIND_EXEC | KIND_EXIT => {
            if data.len() < RAW_EXEC_LEN {
                return None;
            }
            let event = RawExecEvent {
                pid: read_u32(data, 4)?,
                ppid: read_u32(data, 8)?,
                uid: read_u32(data, 12)?,
                comm: read_array(data, 16)?,
            };
            Some(if kind == KIND_EXEC {
                RawEvent::Exec(event)
            } else {
                RawEvent::Exit(event)
            })
        }
        KIND_CONNECT | KIND_LISTEN => {
            if data.len() < RAW_NET_LEN {
                return None;
            }
            let event = RawNetEvent {
                kind,
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                family: read_u32(data, 12)?,
                sport: read_u32(data, 16)?,
                dport: read_u32(data, 20)?,
                addr: read_array(data, 24)?,
                comm: read_array(data, 40)?,
            };
            Some(if kind == KIND_CONNECT {
                RawEvent::Connect(event)
            } else {
                RawEvent::Listen(event)
            })
        }
        KIND_ACCEPT => {
            if data.len() < RAW_ACCEPT_LEN {
                return None;
            }
            Some(RawEvent::Accept(RawAcceptEvent {
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                fd: read_u32(data, 12)?,
                listen_fd: read_u32(data, 16)?,
                family: read_u32(data, 20)?,
                port: read_u32(data, 24)?,
                addr: read_array(data, 28)?,
                comm: read_array(data, 44)?,
            }))
        }
        KIND_FD_DUP | KIND_FD_CLOSE => {
            if data.len() < RAW_FD_LEN {
                return None;
            }
            let event = RawFdEvent {
                kind,
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                oldfd: read_u32(data, 12)?,
                newfd: read_u32(data, 16)?,
                comm: read_array(data, 20)?,
            };
            Some(if kind == KIND_FD_DUP {
                RawEvent::FdDup(event)
            } else {
                RawEvent::FdClose(event)
            })
        }
        KIND_FILE_OPEN | KIND_FILE_UNLINK => {
            if data.len() < RAW_PATH_LEN {
                return None;
            }
            let event = RawPathEvent {
                kind,
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                flags: read_u32(data, 12)?,
                fd: read_u32(data, 16)?,
                comm: read_array(data, 20)?,
                path: read_array(data, 36)?,
            };
            Some(if kind == KIND_FILE_OPEN {
                RawEvent::FileOpen(event)
            } else {
                RawEvent::FileUnlink(event)
            })
        }
        KIND_FILE_WRITE => {
            if data.len() < RAW_WRITE_LEN {
                return None;
            }
            Some(RawEvent::FileWrite(RawWriteEvent {
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                fd: read_u32(data, 12)?,
                count: u64::from_le_bytes(data.get(16..24)?.try_into().ok()?),
                comm: read_array(data, 24)?,
            }))
        }
        KIND_FILE_RENAME => {
            if data.len() < RAW_RENAME_LEN {
                return None;
            }
            Some(RawEvent::FileRename(Box::new(RawRenameEvent {
                kind,
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                comm: read_array(data, 16)?,
                old_path: read_array(data, 32)?,
                new_path: read_array(data, 544)?,
            })))
        }
        _ => None,
    }
}

#[derive(Debug, Default)]
pub struct AttachReport {
    pub attached: Vec<String>,
    pub skipped: Vec<String>,
}

impl AttachReport {
    fn attach(&mut self, name: &str) {
        self.attached.push(name.to_string());
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped.push(format!("{name}: {reason}"));
    }
}

pub struct Collector {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
    net_totals: Option<HashMap<MapData, u32, NetTotals>>,
    /// Perf event descriptors keep every per-CPU attachment alive. Closing
    /// them detaches the programs; no debugfs bookkeeping is required.
    _perf_links: Vec<OwnedFd>,
}

impl Collector {
    pub fn load(object_path: &Path) -> Result<(Self, AttachReport)> {
        if !probe::ringbuf_supported() {
            anyhow::bail!(
                "kernel {} lacks BPF ring buffer support (need >= {}.{}); \
                 electric-eyed requires a newer kernel",
                probe::kernel_release(),
                probe::MIN_KERNEL.0,
                probe::MIN_KERNEL.1
            );
        }

        let mut bpf = Ebpf::load_file(object_path)
            .with_context(|| format!("failed to load eBPF object {}", object_path.display()))?;
        let mut report = AttachReport::default();
        let mut perf_links = Vec::new();

        let sock_ok = fill_sock_offsets(&mut bpf, &mut report);
        let syscall_plan = fill_syscall_offsets(&mut bpf, &mut report);

        let ksyms = match probe::available_ksyms() {
            Ok(ksyms) => Some(ksyms),
            Err(err) => {
                log::warn!("kallsyms unavailable ({err}); traffic accounting disabled");
                None
            }
        };

        attach_tracepoint(
            &mut bpf,
            &mut report,
            &mut perf_links,
            PROGRAM_EXEC,
            "sched",
            "sched_process_exec",
            true,
        )?;
        attach_tracepoint(
            &mut bpf,
            &mut report,
            &mut perf_links,
            PROGRAM_EXIT,
            "sched",
            "sched_process_exit",
            false,
        )?;

        if sock_ok {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                &mut perf_links,
                "electric_eye_sock_state",
                "sock",
                "inet_sock_set_state",
                false,
            )?;
        } else {
            report.skip("electric_eye_sock_state", "tracepoint layout unresolved");
        }

        for (enabled, program, category, event) in [
            (
                syscall_plan.openat,
                "electric_eye_openat",
                "syscalls",
                "sys_enter_openat",
            ),
            (
                syscall_plan.openat,
                "electric_eye_openat_exit",
                "syscalls",
                "sys_exit_openat",
            ),
            (
                syscall_plan.openat2,
                "electric_eye_openat2",
                "syscalls",
                "sys_enter_openat2",
            ),
            (
                syscall_plan.openat2,
                "electric_eye_openat2_exit",
                "syscalls",
                "sys_exit_openat2",
            ),
            (
                syscall_plan.open,
                "electric_eye_open",
                "syscalls",
                "sys_enter_open",
            ),
            (
                syscall_plan.open,
                "electric_eye_open_exit",
                "syscalls",
                "sys_exit_open",
            ),
            (
                syscall_plan.unlinkat,
                "electric_eye_unlinkat",
                "syscalls",
                "sys_enter_unlinkat",
            ),
            (
                syscall_plan.unlink,
                "electric_eye_unlink",
                "syscalls",
                "sys_enter_unlink",
            ),
            (
                syscall_plan.rmdir,
                "electric_eye_rmdir",
                "syscalls",
                "sys_enter_rmdir",
            ),
            (
                syscall_plan.rename,
                "electric_eye_rename",
                "syscalls",
                "sys_enter_rename",
            ),
            (
                syscall_plan.renameat,
                "electric_eye_renameat",
                "syscalls",
                "sys_enter_renameat",
            ),
            (
                syscall_plan.renameat2,
                "electric_eye_renameat2",
                "syscalls",
                "sys_enter_renameat2",
            ),
            (
                syscall_plan.write,
                "electric_eye_write",
                "syscalls",
                "sys_enter_write",
            ),
            (
                syscall_plan.accept,
                "electric_eye_accept_enter",
                "syscalls",
                "sys_enter_accept",
            ),
            (
                syscall_plan.accept,
                "electric_eye_accept_exit",
                "syscalls",
                "sys_exit_accept",
            ),
            (
                syscall_plan.accept4,
                "electric_eye_accept4_enter",
                "syscalls",
                "sys_enter_accept4",
            ),
            (
                syscall_plan.accept4,
                "electric_eye_accept4_exit",
                "syscalls",
                "sys_exit_accept4",
            ),
            (
                syscall_plan.dup2,
                "electric_eye_dup2",
                "syscalls",
                "sys_enter_dup2",
            ),
            (
                syscall_plan.dup3,
                "electric_eye_dup3",
                "syscalls",
                "sys_enter_dup3",
            ),
            (
                syscall_plan.close,
                "electric_eye_close",
                "syscalls",
                "sys_enter_close",
            ),
        ] {
            if enabled {
                attach_tracepoint(
                    &mut bpf,
                    &mut report,
                    &mut perf_links,
                    program,
                    category,
                    event,
                    false,
                )?;
            }
        }

        if let Some(ksyms) = &ksyms {
            for (symbol, program) in [
                ("tcp_sendmsg", "electric_eye_tcp_sent"),
                ("tcp_recvmsg", "electric_eye_tcp_recv"),
                ("udp_sendmsg", "electric_eye_udp_sent"),
                ("udp_recvmsg", "electric_eye_udp_recv"),
            ] {
                if ksyms.contains(symbol) {
                    match attach_kretprobe(&mut bpf, &mut perf_links, program, symbol) {
                        Ok(()) => report.attach(program),
                        Err(err) => report.skip(program, &format!("{err:#}")),
                    }
                } else {
                    report.skip(program, &format!("symbol {symbol} absent from kallsyms"));
                }
            }
        }

        let ring = RingBuf::try_from(
            bpf.take_map(EVENT_MAP)
                .with_context(|| format!("map {EVENT_MAP} missing from the object"))?,
        )?;

        let net_totals = bpf
            .take_map("NET_BYTES")
            .map(HashMap::try_from)
            .transpose()?;

        Ok((
            Self {
                _bpf: bpf,
                ring,
                net_totals,
                _perf_links: perf_links,
            },
            report,
        ))
    }

    pub fn drain_once<F: FnMut(RawEvent)>(&mut self, handler: &mut F) -> Result<usize> {
        const MAX_EVENTS_PER_CALL: usize = 4096;
        let mut count = 0;
        while count < MAX_EVENTS_PER_CALL {
            let Some(item) = self.ring.next() else {
                break;
            };
            match decode(&item) {
                Some(event) => {
                    handler(event);
                    count += 1;
                }
                None => anyhow::bail!("malformed event of {} bytes", item.len()),
            }
        }
        Ok(count)
    }

    pub fn drain_net_totals(&mut self) -> Result<Vec<(u32, u64, u64)>> {
        let Some(map) = &mut self.net_totals else {
            return Ok(Vec::new());
        };
        let mut snapshot = Vec::new();
        for item in map.iter() {
            let (pid, totals) = item.context("net totals iteration failed")?;
            snapshot.push((pid, totals.sent, totals.recv));
        }
        for (pid, _, _) in &snapshot {
            map.insert(*pid, NetTotals { sent: 0, recv: 0 }, 0)?;
        }
        Ok(snapshot)
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

fn attach_kretprobe(
    bpf: &mut Ebpf,
    perf_links: &mut Vec<OwnedFd>,
    program: &str,
    symbol: &str,
) -> Result<()> {
    let pmu_type = read_trimmed("/sys/bus/event_source/devices/kprobe/type")
        .context("kprobe PMU type unavailable")?
        .parse::<u32>()
        .context("invalid kprobe PMU type")?;
    let retprobe_bit = match read_trimmed("/sys/bus/event_source/devices/kprobe/format/retprobe") {
        Ok(text) => Some(
            text.split_once(':')
                .context("invalid retprobe format")?
                .1
                .parse::<u32>()
                .context("invalid retprobe bit")?,
        ),
        Err(err) => {
            log::warn!("kprobe retprobe format unavailable ({err}); using entry probes");
            None
        }
    };

    let name = CString::new(symbol).context("kprobe symbol contains a NUL byte")?;
    let kp: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from the object"))?
        .try_into()?;
    kp.load()?;
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

fn fill_sock_offsets(bpf: &mut Ebpf, report: &mut AttachReport) -> bool {
    match publish_sock_offsets(bpf) {
        Ok(()) => true,
        Err(err) => {
            report.skip("sock offsets", &format!("{err:#}"));
            false
        }
    }
}

fn publish_sock_offsets(bpf: &mut Ebpf) -> Result<()> {
    let fmt = TraceFormat::load("sock", "inet_sock_set_state")
        .context("inet_sock_set_state format unavailable")?;
    let resolve = |field: &str| {
        fmt.offset(field)
            .map(|o| o as u32)
            .ok_or_else(|| anyhow::anyhow!("inet_sock_set_state is missing field {field}"))
    };
    let offsets = SockOffsets {
        oldstate: resolve("oldstate")?,
        newstate: resolve("newstate")?,
        sport: resolve("sport")?,
        dport: resolve("dport")?,
        family: resolve("family")?,
        protocol: resolve("protocol")?,
        saddr4: resolve("saddr")?,
        daddr4: resolve("daddr")?,
        saddr6: resolve("saddr_v6")?,
        daddr6: resolve("daddr_v6")?,
    };
    let mut map: HashMap<&mut MapData, u32, SockOffsets> = bpf
        .map_mut("SOCK_OFFSETS")
        .context("SOCK_OFFSETS map missing")?
        .try_into()?;
    map.insert(0, offsets, 0)
        .context("failed to publish socket offsets")?;
    Ok(())
}

fn fill_syscall_offsets(bpf: &mut Ebpf, report: &mut AttachReport) -> SyscallPlan {
    let mut plan = SyscallPlan::default();
    let mut offsets = SyscallOffsets {
        openat_filename: UNRESOLVED_OFFSET,
        openat_flags: UNRESOLVED_OFFSET,
        openat_ret: UNRESOLVED_OFFSET,
        openat2_filename: UNRESOLVED_OFFSET,
        openat2_how: UNRESOLVED_OFFSET,
        openat2_ret: UNRESOLVED_OFFSET,
        open_filename: UNRESOLVED_OFFSET,
        open_flags: UNRESOLVED_OFFSET,
        open_ret: UNRESOLVED_OFFSET,
        unlinkat_pathname: UNRESOLVED_OFFSET,
        unlink_pathname: UNRESOLVED_OFFSET,
        rmdir_pathname: UNRESOLVED_OFFSET,
        rename_oldname: UNRESOLVED_OFFSET,
        rename_newname: UNRESOLVED_OFFSET,
        renameat_oldname: UNRESOLVED_OFFSET,
        renameat_newname: UNRESOLVED_OFFSET,
        renameat2_oldname: UNRESOLVED_OFFSET,
        renameat2_newname: UNRESOLVED_OFFSET,
        write_fd: UNRESOLVED_OFFSET,
        write_count: UNRESOLVED_OFFSET,
        accept_ret: UNRESOLVED_OFFSET,
        accept4_ret: UNRESOLVED_OFFSET,
        accept_fd: UNRESOLVED_OFFSET,
        accept_sockaddr: UNRESOLVED_OFFSET,
        accept_addrlen: UNRESOLVED_OFFSET,
        accept4_fd: UNRESOLVED_OFFSET,
        accept4_sockaddr: UNRESOLVED_OFFSET,
        accept4_addrlen: UNRESOLVED_OFFSET,
        dup2_oldfd: UNRESOLVED_OFFSET,
        dup2_newfd: UNRESOLVED_OFFSET,
        dup3_oldfd: UNRESOLVED_OFFSET,
        dup3_newfd: UNRESOLVED_OFFSET,
        close_fd: UNRESOLVED_OFFSET,
    };

    let openat_enter = resolve_syscall(
        "sys_enter_openat",
        &mut [
            ("filename", &mut offsets.openat_filename),
            ("flags", &mut offsets.openat_flags),
        ],
        report,
        "electric_eye_openat",
    );
    let openat_exit = resolve_syscall(
        "sys_exit_openat",
        &mut [("ret", &mut offsets.openat_ret)],
        report,
        "electric_eye_openat_exit",
    );
    plan.openat = openat_enter && openat_exit;

    let openat2_enter = resolve_syscall(
        "sys_enter_openat2",
        &mut [
            ("filename", &mut offsets.openat2_filename),
            ("how", &mut offsets.openat2_how),
        ],
        report,
        "electric_eye_openat2",
    );
    let openat2_exit = resolve_syscall(
        "sys_exit_openat2",
        &mut [("ret", &mut offsets.openat2_ret)],
        report,
        "electric_eye_openat2_exit",
    );
    plan.openat2 = openat2_enter && openat2_exit;

    let open_enter = resolve_syscall(
        "sys_enter_open",
        &mut [
            ("filename", &mut offsets.open_filename),
            ("flags", &mut offsets.open_flags),
        ],
        report,
        "electric_eye_open",
    );
    let open_exit = resolve_syscall(
        "sys_exit_open",
        &mut [("ret", &mut offsets.open_ret)],
        report,
        "electric_eye_open_exit",
    );
    plan.open = open_enter && open_exit;
    plan.unlinkat = resolve_syscall(
        "sys_enter_unlinkat",
        &mut [("pathname", &mut offsets.unlinkat_pathname)],
        report,
        "electric_eye_unlinkat",
    );
    plan.unlink = resolve_syscall(
        "sys_enter_unlink",
        &mut [("pathname", &mut offsets.unlink_pathname)],
        report,
        "electric_eye_unlink",
    );
    plan.rmdir = resolve_syscall(
        "sys_enter_rmdir",
        &mut [("pathname", &mut offsets.rmdir_pathname)],
        report,
        "electric_eye_rmdir",
    );
    plan.rename = resolve_syscall(
        "sys_enter_rename",
        &mut [
            ("oldname", &mut offsets.rename_oldname),
            ("newname", &mut offsets.rename_newname),
        ],
        report,
        "electric_eye_rename",
    );
    plan.renameat = resolve_syscall(
        "sys_enter_renameat",
        &mut [
            ("oldname", &mut offsets.renameat_oldname),
            ("newname", &mut offsets.renameat_newname),
        ],
        report,
        "electric_eye_renameat",
    );
    plan.renameat2 = resolve_syscall(
        "sys_enter_renameat2",
        &mut [
            ("oldname", &mut offsets.renameat2_oldname),
            ("newname", &mut offsets.renameat2_newname),
        ],
        report,
        "electric_eye_renameat2",
    );
    plan.write = resolve_syscall(
        "sys_enter_write",
        &mut [
            ("fd", &mut offsets.write_fd),
            ("count", &mut offsets.write_count),
        ],
        report,
        "electric_eye_write",
    );
    let accept_enter = resolve_syscall(
        "sys_enter_accept",
        &mut [
            ("fd", &mut offsets.accept_fd),
            ("upeer_sockaddr", &mut offsets.accept_sockaddr),
            ("upeer_addrlen", &mut offsets.accept_addrlen),
        ],
        report,
        "electric_eye_accept_enter",
    );
    let accept_exit = resolve_syscall(
        "sys_exit_accept",
        &mut [("ret", &mut offsets.accept_ret)],
        report,
        "electric_eye_accept_exit",
    );
    plan.accept = accept_enter && accept_exit;

    let accept4_enter = resolve_syscall(
        "sys_enter_accept4",
        &mut [
            ("fd", &mut offsets.accept4_fd),
            ("upeer_sockaddr", &mut offsets.accept4_sockaddr),
            ("upeer_addrlen", &mut offsets.accept4_addrlen),
        ],
        report,
        "electric_eye_accept4_enter",
    );
    let accept4_exit = resolve_syscall(
        "sys_exit_accept4",
        &mut [("ret", &mut offsets.accept4_ret)],
        report,
        "electric_eye_accept4_exit",
    );
    plan.accept4 = accept4_enter && accept4_exit;
    plan.dup2 = resolve_syscall(
        "sys_enter_dup2",
        &mut [
            ("oldfd", &mut offsets.dup2_oldfd),
            ("newfd", &mut offsets.dup2_newfd),
        ],
        report,
        "electric_eye_dup2",
    );
    plan.dup3 = resolve_syscall(
        "sys_enter_dup3",
        &mut [
            ("oldfd", &mut offsets.dup3_oldfd),
            ("newfd", &mut offsets.dup3_newfd),
        ],
        report,
        "electric_eye_dup3",
    );
    plan.close = resolve_syscall(
        "sys_enter_close",
        &mut [("fd", &mut offsets.close_fd)],
        report,
        "electric_eye_close",
    );

    if plan.any() {
        let publish = (|| -> Result<()> {
            let mut map: HashMap<&mut MapData, u32, SyscallOffsets> = bpf
                .map_mut("SYSCALL_OFFSETS")
                .context("SYSCALL_OFFSETS map missing")?
                .try_into()?;
            map.insert(0, offsets, 0)
                .context("failed to publish syscall offsets")
        })();
        match publish {
            Ok(()) => (),
            Err(err) => {
                report.skip("syscall offsets", &format!("{err:#}"));
                plan = SyscallPlan::default();
            }
        }
    }
    plan
}

fn resolve_syscall(
    event: &str,
    fields: &mut [(&str, &mut u32)],
    report: &mut AttachReport,
    program: &str,
) -> bool {
    let fmt = match TraceFormat::load("syscalls", event) {
        Ok(fmt) => fmt,
        Err(err) => {
            report.skip(program, &format!("{event}: {err}"));
            return false;
        }
    };
    for (field, slot) in fields {
        match fmt.offset(field) {
            Some(offset) => **slot = offset as u32,
            None => {
                report.skip(program, &format!("{event} is missing field {field}"));
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallPlan {
    openat: bool,
    openat2: bool,
    open: bool,
    unlinkat: bool,
    unlink: bool,
    rmdir: bool,
    rename: bool,
    renameat: bool,
    renameat2: bool,
    write: bool,
    accept: bool,
    accept4: bool,
    dup2: bool,
    dup3: bool,
    close: bool,
}

impl SyscallPlan {
    fn any(&self) -> bool {
        self.openat
            || self.openat2
            || self.open
            || self.unlinkat
            || self.unlink
            || self.rmdir
            || self.rename
            || self.renameat
            || self.renameat2
            || self.write
            || self.accept
            || self.accept4
            || self.dup2
            || self.dup3
            || self.close
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exec_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_EXEC.to_le_bytes());
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&7_u32.to_le_bytes());
        data.extend_from_slice(&1000_u32.to_le_bytes());
        let mut comm = [0_u8; 16];
        comm[..4].copy_from_slice(b"bash");
        data.extend_from_slice(&comm);
        match decode(&data) {
            Some(RawEvent::Exec(event)) => {
                assert_eq!(event.pid, 42);
                assert_eq!(event.ppid, 7);
                assert_eq!(event.comm_str(), "bash");
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn decodes_accept_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_ACCEPT.to_le_bytes());
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&1000_u32.to_le_bytes());
        data.extend_from_slice(&7_u32.to_le_bytes());
        data.extend_from_slice(&3_u32.to_le_bytes());
        data.extend_from_slice(&2_u32.to_le_bytes());
        data.extend_from_slice(&51000_u32.to_le_bytes());
        data.extend_from_slice(&[127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut comm = [0_u8; 16];
        comm[..6].copy_from_slice(b"python");
        data.extend_from_slice(&comm);
        match decode(&data) {
            Some(RawEvent::Accept(event)) => {
                assert_eq!(event.pid, 42);
                assert_eq!(event.fd, 7);
                assert_eq!(event.listen_fd, 3);
                assert_eq!(event.family, 2);
                assert_eq!(event.port, 51000);
                assert_eq!(&event.addr[..4], &[127, 0, 0, 1]);
                assert_eq!(event.comm_str(), "python");
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn decodes_fd_dup_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_FD_DUP.to_le_bytes());
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&1000_u32.to_le_bytes());
        data.extend_from_slice(&3_u32.to_le_bytes());
        data.extend_from_slice(&1_u32.to_le_bytes());
        let mut comm = [0_u8; 16];
        comm[..2].copy_from_slice(b"sh");
        data.extend_from_slice(&comm);
        match decode(&data) {
            Some(RawEvent::FdDup(event)) => {
                assert_eq!(event.oldfd, 3);
                assert_eq!(event.newfd, 1);
                assert_eq!(event.comm_str(), "sh");
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn decodes_write_event() {
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_FILE_WRITE.to_le_bytes());
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&1000_u32.to_le_bytes());
        data.extend_from_slice(&3_u32.to_le_bytes());
        data.extend_from_slice(&4096_u64.to_le_bytes());
        let mut comm = [0_u8; 16];
        comm[..2].copy_from_slice(b"sh");
        data.extend_from_slice(&comm);
        match decode(&data) {
            Some(RawEvent::FileWrite(event)) => {
                assert_eq!(event.fd, 3);
                assert_eq!(event.count, 4096);
                assert_eq!(event.comm_str(), "sh");
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn decodes_open_flags() {
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_FILE_OPEN.to_le_bytes());
        data.extend_from_slice(&42_u32.to_le_bytes());
        data.extend_from_slice(&1000_u32.to_le_bytes());
        data.extend_from_slice(&0o1101_u32.to_le_bytes());
        data.extend_from_slice(&7_u32.to_le_bytes());
        data.extend_from_slice(&[0_u8; 16]);
        data.extend_from_slice(&[0_u8; 512]);
        match decode(&data) {
            Some(RawEvent::FileOpen(event)) => {
                assert_eq!(event.flags, 0o1101);
                assert_eq!(event.fd, 7);
                assert_eq!(event.pid, 42);
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_event() {
        assert!(decode(&[0, 0, 0]).is_none());
        let mut data = Vec::new();
        data.extend_from_slice(&KIND_FILE_RENAME.to_le_bytes());
        data.extend_from_slice(&[0; 64]);
        assert!(decode(&data).is_none());
    }
}
