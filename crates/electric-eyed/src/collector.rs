use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, RingBuf};
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, Pod};

use crate::format::TraceFormat;
use crate::probe;

pub const EVENT_MAP: &str = "EVENTS";
pub const PROGRAM_EXEC: &str = "electric_eye_exec";

const RAW_EXEC_LEN: usize = 32;
const RAW_NET_LEN: usize = 56;
const RAW_PATH_LEN: usize = 288;
const RAW_RENAME_LEN: usize = 544;

const UNRESOLVED_OFFSET: u32 = u32::MAX;

pub const KIND_EXEC: u32 = 0;
pub const KIND_CONNECT: u32 = 1;
pub const KIND_LISTEN: u32 = 2;
pub const KIND_FILE_WRITE: u32 = 3;
pub const KIND_FILE_UNLINK: u32 = 4;
pub const KIND_FILE_RENAME: u32 = 5;

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
#[derive(Clone, Copy, Default)]
pub struct SyscallOffsets {
    pub openat_filename: u32,
    pub openat_flags: u32,
    pub unlinkat_pathname: u32,
    pub rename_oldname: u32,
    pub rename_newname: u32,
}

unsafe impl Pod for SyscallOffsets {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetTotals {
    pub sent: u64,
    pub recv: u64,
}

unsafe impl Pod for NetTotals {}

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
    pub comm: [u8; 16],
    pub path: [u8; 256],
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
pub struct RawRenameEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub old_path: [u8; 256],
    pub new_path: [u8; 256],
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
    Connect(RawNetEvent),
    Listen(RawNetEvent),
    FileWrite(RawPathEvent),
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
        KIND_EXEC => {
            if data.len() < RAW_EXEC_LEN {
                return None;
            }
            Some(RawEvent::Exec(RawExecEvent {
                pid: read_u32(data, 4)?,
                ppid: read_u32(data, 8)?,
                uid: read_u32(data, 12)?,
                comm: read_array(data, 16)?,
            }))
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
        KIND_FILE_WRITE | KIND_FILE_UNLINK => {
            if data.len() < RAW_PATH_LEN {
                return None;
            }
            let event = RawPathEvent {
                kind,
                pid: read_u32(data, 4)?,
                uid: read_u32(data, 8)?,
                comm: read_array(data, 16)?,
                path: read_array(data, 32)?,
            };
            Some(if kind == KIND_FILE_WRITE {
                RawEvent::FileWrite(event)
            } else {
                RawEvent::FileUnlink(event)
            })
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
                new_path: read_array(data, 288)?,
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
            PROGRAM_EXEC,
            "sched",
            "sched_process_exec",
            true,
        )?;

        if sock_ok {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                "electric_eye_sock_state",
                "sock",
                "inet_sock_set_state",
                false,
            )?;
        } else {
            report.skip("electric_eye_sock_state", "tracepoint layout unresolved");
        }

        if syscall_plan.openat {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                "electric_eye_openat",
                "syscalls",
                "sys_enter_openat",
                false,
            )?;
        }
        if syscall_plan.unlinkat {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                "electric_eye_unlinkat",
                "syscalls",
                "sys_enter_unlinkat",
                false,
            )?;
        }
        if syscall_plan.renameat2 {
            attach_tracepoint(
                &mut bpf,
                &mut report,
                "electric_eye_renameat2",
                "syscalls",
                "sys_enter_renameat2",
                false,
            )?;
        }

        if let Some(ksyms) = &ksyms {
            for (symbol, program) in [
                ("tcp_sendmsg", "electric_eye_tcp_sent"),
                ("tcp_recvmsg", "electric_eye_tcp_recv"),
                ("udp_sendmsg", "electric_eye_udp_sent"),
                ("udp_recvmsg", "electric_eye_udp_recv"),
            ] {
                if ksyms.contains(symbol) {
                    match attach_kretprobe(&mut bpf, program, symbol) {
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
            },
            report,
        ))
    }

    pub fn drain_once<F: FnMut(RawEvent)>(&mut self, handler: &mut F) -> Result<usize> {
        let mut count = 0;
        while let Some(item) = self.ring.next() {
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
    program: &str,
    category: &str,
    event: &str,
    required: bool,
) -> Result<()> {
    let result = (|| -> Result<()> {
        let tp: &mut TracePoint = bpf
            .program_mut(program)
            .with_context(|| format!("program {program} missing from the object"))?
            .try_into()?;
        tp.load()?;
        tp.attach(category, event)
            .with_context(|| format!("failed to attach {category}/{event}"))?;
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

fn attach_kretprobe(bpf: &mut Ebpf, program: &str, symbol: &str) -> Result<()> {
    let kp: &mut KProbe = bpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from the object"))?
        .try_into()?;
    kp.load()?;
    kp.attach(symbol, 0)
        .with_context(|| format!("failed to attach kretprobe:{symbol}"))?;
    Ok(())
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
        unlinkat_pathname: UNRESOLVED_OFFSET,
        rename_oldname: UNRESOLVED_OFFSET,
        rename_newname: UNRESOLVED_OFFSET,
    };

    match TraceFormat::load("syscalls", "sys_enter_openat") {
        Ok(fmt) => match (fmt.offset("filename"), fmt.offset("flags")) {
            (Some(f), Some(fl)) => {
                offsets.openat_filename = f as u32;
                offsets.openat_flags = fl as u32;
                plan.openat = true;
            }
            _ => report.skip("electric_eye_openat", "required fields absent"),
        },
        Err(err) => report.skip("electric_eye_openat", &format!("{err}")),
    }

    match TraceFormat::load("syscalls", "sys_enter_unlinkat") {
        Ok(fmt) => match fmt.offset("pathname") {
            Some(off) => {
                offsets.unlinkat_pathname = off as u32;
                plan.unlinkat = true;
            }
            None => report.skip("electric_eye_unlinkat", "pathname field absent"),
        },
        Err(err) => report.skip("electric_eye_unlinkat", &format!("{err}")),
    }

    match TraceFormat::load("syscalls", "sys_enter_renameat2") {
        Ok(fmt) => match (fmt.offset("oldname"), fmt.offset("newname")) {
            (Some(old), Some(new)) => {
                offsets.rename_oldname = old as u32;
                offsets.rename_newname = new as u32;
                plan.renameat2 = true;
            }
            _ => report.skip("electric_eye_renameat2", "required fields absent"),
        },
        Err(err) => report.skip("electric_eye_renameat2", &format!("{err}")),
    }

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

#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallPlan {
    openat: bool,
    unlinkat: bool,
    renameat2: bool,
}

impl SyscallPlan {
    fn any(&self) -> bool {
        self.openat || self.unlinkat || self.renameat2
    }
}
