#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kretprobe, map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::{RetProbeContext, TracePointContext},
};

pub const KIND_EXEC: u32 = 0;
pub const KIND_CONNECT: u32 = 1;
pub const KIND_LISTEN: u32 = 2;
pub const KIND_FILE_WRITE: u32 = 3;
pub const KIND_FILE_UNLINK: u32 = 4;
pub const KIND_FILE_RENAME: u32 = 5;
pub const KIND_EXIT: u32 = 6;
pub const KIND_ACCEPT: u32 = 7;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;

const TCP_ESTABLISHED: i32 = 1;
const TCP_SYN_SENT: i32 = 2;
const TCP_SYN_RECV: i32 = 3;
const TCP_LISTEN: i32 = 10;

const O_ACCMODE: i32 = 0o3;
const O_RDONLY: i32 = 0o0;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;

const PATH_LEN: usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallOffsets {
    pub openat_filename: u32,
    pub openat_flags: u32,
    pub openat2_filename: u32,
    pub openat2_how: u32,
    pub open_filename: u32,
    pub open_flags: u32,
    pub unlinkat_pathname: u32,
    pub unlink_pathname: u32,
    pub rmdir_pathname: u32,
    pub rename_oldname: u32,
    pub rename_newname: u32,
    pub renameat_oldname: u32,
    pub renameat_newname: u32,
    pub renameat2_oldname: u32,
    pub renameat2_newname: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetTotals {
    pub sent: u64,
    pub recv: u64,
}

#[repr(C)]
pub struct RawExecEvent {
    pub kind: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
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

#[repr(C)]
pub struct RawPathEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub pad: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
}

#[repr(C)]
pub struct RawRenameEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub pad: u32,
    pub comm: [u8; 16],
    pub old_path: [u8; PATH_LEN],
    pub new_path: [u8; PATH_LEN],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 21, 0);

#[map]
static SOCK_OFFSETS: HashMap<u32, SockOffsets> = HashMap::with_max_entries(1, 0);

#[map]
static SYSCALL_OFFSETS: HashMap<u32, SyscallOffsets> = HashMap::with_max_entries(1, 0);

#[map]
static NET_BYTES: HashMap<u32, NetTotals> = HashMap::with_max_entries(16384, 0);

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

fn current_ids() -> (u32, u32) {
    (current_tgid(), bpf_get_current_uid_gid() as u32)
}

fn ctx_read<T>(ctx: &TracePointContext, offset: usize) -> Result<T, ()> {
    unsafe { ctx.read_at::<T>(offset) }.map_err(|_| ())
}

fn current_comm() -> Result<[u8; 16], ()> {
    bpf_get_current_comm().map_err(|_| ())
}

fn push_record<T: 'static>(record: T) -> bool {
    match EVENTS.reserve::<T>(0) {
        Some(mut slot) => {
            slot.write(record);
            slot.submit(0);
            true
        }
        None => false,
    }
}

fn read_user_path(ptr: u64, buf: &mut [u8; PATH_LEN]) -> Result<(), ()> {
    if ptr == 0 {
        return Err(());
    }
    unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, buf) }.map_err(|_| ())?;
    Ok(())
}

fn emit_path_record(p: *mut RawPathEvent, kind: u32, path_ptr: u64) -> bool {
    let Ok(comm) = current_comm() else {
        return false;
    };
    let (pid, uid) = current_ids();
    unsafe {
        (*p).kind = kind;
        (*p).pid = pid;
        (*p).uid = uid;
        (*p).pad = 0;
        (*p).comm = comm;
    }
    read_user_path(path_ptr, unsafe { &mut (*p).path }).is_ok()
}

fn reserve_path_event(kind: u32, path_ptr: u64) {
    let Some(mut slot) = EVENTS.reserve::<RawPathEvent>(0) else {
        return;
    };
    let p = slot.as_mut_ptr();
    if emit_path_record(p, kind, path_ptr) {
        slot.submit(0);
    } else {
        slot.discard(0);
    }
}

fn reserve_rename_event(old_ptr: u64, new_ptr: u64) {
    let Some(mut slot) = EVENTS.reserve::<RawRenameEvent>(0) else {
        return;
    };
    let p = slot.as_mut_ptr();
    let Ok(comm) = current_comm() else {
        slot.discard(0);
        return;
    };
    unsafe {
        (*p).kind = KIND_FILE_RENAME;
        ((*p).pid, (*p).uid) = current_ids();
        (*p).pad = 0;
        (*p).comm = comm;
    }
    let old_ok = read_user_path(old_ptr, unsafe { &mut (*p).old_path }).is_ok();
    let new_ok = read_user_path(new_ptr, unsafe { &mut (*p).new_path }).is_ok();
    if old_ok && new_ok {
        slot.submit(0);
    } else {
        slot.discard(0);
    }
}

fn writable_open(flags: i32) -> bool {
    (flags & O_ACCMODE) != O_RDONLY || (flags & (O_CREAT | O_TRUNC)) != 0
}

#[tracepoint(category = "sched", name = "sched_process_exec")]
fn electric_eye_exec(_ctx: TracePointContext) -> i32 {
    match try_exec() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec() -> Result<(), ()> {
    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();

    push_record(RawExecEvent {
        kind: KIND_EXEC,
        pid,
        ppid: 0,
        uid,
        comm,
    });
    Ok(())
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
fn electric_eye_exit(_ctx: TracePointContext) -> i32 {
    match try_exit() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exit() -> Result<(), ()> {
    // sched_process_exit fires for every thread; only report thread-group
    // leaders so userspace sees one EXIT per process.
    if (bpf_get_current_pid_tgid() as u32) != current_tgid() {
        return Ok(());
    }
    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();
    push_record(RawExecEvent {
        kind: KIND_EXIT,
        pid,
        ppid: 0,
        uid,
        comm,
    });
    Ok(())
}

#[tracepoint(category = "sock", name = "inet_sock_set_state")]
fn electric_eye_sock_state(ctx: TracePointContext) -> i32 {
    match try_sock_state(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_sock_state(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SockOffsets = unsafe { *SOCK_OFFSETS.get(&0).ok_or(())? };

    let oldstate: i32 = ctx_read(ctx, offs.oldstate as usize)?;
    let newstate: i32 = ctx_read(ctx, offs.newstate as usize)?;
    let kind = match newstate {
        TCP_SYN_SENT => KIND_CONNECT,
        TCP_LISTEN => KIND_LISTEN,
        TCP_ESTABLISHED if oldstate == TCP_SYN_RECV => KIND_ACCEPT,
        _ => return Ok(()),
    };

    let family: u16 = ctx_read(ctx, offs.family as usize)?;
    if family != AF_INET && family != AF_INET6 {
        return Ok(());
    }
    let protocol: u16 = ctx_read(ctx, offs.protocol as usize)?;
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    let sport: u16 = ctx_read(ctx, offs.sport as usize)?;
    let dport: u16 = ctx_read(ctx, offs.dport as usize)?;

    let remote = matches!(kind, KIND_CONNECT | KIND_ACCEPT);
    let mut addr = [0u8; 16];
    match family {
        AF_INET => {
            let raw: u32 = if remote {
                ctx_read(ctx, offs.daddr4 as usize)?
            } else {
                ctx_read(ctx, offs.saddr4 as usize)?
            };
            addr[..4].copy_from_slice(&raw.to_ne_bytes());
        }
        AF_INET6 => {
            addr = if remote {
                ctx_read(ctx, offs.daddr6 as usize)?
            } else {
                ctx_read(ctx, offs.saddr6 as usize)?
            };
        }
        _ => return Ok(()),
    }

    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();

    push_record(RawNetEvent {
        kind,
        pid,
        uid,
        family: family as u32,
        sport: sport as u32,
        dport: dport as u32,
        addr,
        comm,
    });
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
fn electric_eye_openat(ctx: TracePointContext) -> i32 {
    match try_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_openat(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let flags: i32 = ctx_read(ctx, offs.openat_flags as usize)?;
    if !writable_open(flags) {
        return Ok(());
    }
    let filename: u64 = ctx_read(ctx, offs.openat_filename as usize)?;
    reserve_path_event(KIND_FILE_WRITE, filename);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat2")]
fn electric_eye_openat2(ctx: TracePointContext) -> i32 {
    match try_openat2(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_openat2(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let how: u64 = ctx_read(ctx, offs.openat2_how as usize)?;
    if how == 0 {
        return Ok(());
    }
    let flags: u64 = unsafe { bpf_probe_read_user(how as *const u64) }.map_err(|_| ())?;
    if !writable_open(flags as i32) {
        return Ok(());
    }
    let filename: u64 = ctx_read(ctx, offs.openat2_filename as usize)?;
    reserve_path_event(KIND_FILE_WRITE, filename);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_open")]
fn electric_eye_open(ctx: TracePointContext) -> i32 {
    match try_open(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_open(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let flags: i32 = ctx_read(ctx, offs.open_flags as usize)?;
    if !writable_open(flags) {
        return Ok(());
    }
    let filename: u64 = ctx_read(ctx, offs.open_filename as usize)?;
    reserve_path_event(KIND_FILE_WRITE, filename);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlinkat")]
fn electric_eye_unlinkat(ctx: TracePointContext) -> i32 {
    match try_unlinkat(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_unlinkat(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let pathname: u64 = ctx_read(ctx, offs.unlinkat_pathname as usize)?;
    reserve_path_event(KIND_FILE_UNLINK, pathname);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_unlink")]
fn electric_eye_unlink(ctx: TracePointContext) -> i32 {
    match try_unlink(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_unlink(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let pathname: u64 = ctx_read(ctx, offs.unlink_pathname as usize)?;
    reserve_path_event(KIND_FILE_UNLINK, pathname);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_rmdir")]
fn electric_eye_rmdir(ctx: TracePointContext) -> i32 {
    match try_rmdir(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_rmdir(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let pathname: u64 = ctx_read(ctx, offs.rmdir_pathname as usize)?;
    reserve_path_event(KIND_FILE_UNLINK, pathname);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_rename")]
fn electric_eye_rename(ctx: TracePointContext) -> i32 {
    match try_rename(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_renameat")]
fn electric_eye_renameat(ctx: TracePointContext) -> i32 {
    match try_rename(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_rename(ctx: &TracePointContext, at: bool) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let (old_off, new_off) = if at {
        (offs.renameat_oldname, offs.renameat_newname)
    } else {
        (offs.rename_oldname, offs.rename_newname)
    };
    let oldname: u64 = ctx_read(ctx, old_off as usize)?;
    let newname: u64 = ctx_read(ctx, new_off as usize)?;
    reserve_rename_event(oldname, newname);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_renameat2")]
fn electric_eye_renameat2(ctx: TracePointContext) -> i32 {
    match try_renameat2(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_renameat2(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let oldname: u64 = ctx_read(ctx, offs.renameat2_oldname as usize)?;
    let newname: u64 = ctx_read(ctx, offs.renameat2_newname as usize)?;
    reserve_rename_event(oldname, newname);
    Ok(())
}

#[kretprobe]
fn electric_eye_tcp_sent(ctx: RetProbeContext) -> i32 {
    match try_traffic(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[kretprobe]
fn electric_eye_tcp_recv(ctx: RetProbeContext) -> i32 {
    match try_traffic(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[kretprobe]
fn electric_eye_udp_sent(ctx: RetProbeContext) -> i32 {
    match try_traffic(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[kretprobe]
fn electric_eye_udp_recv(ctx: RetProbeContext) -> i32 {
    match try_traffic(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_traffic(ctx: &RetProbeContext, sent: bool) -> Result<(), ()> {
    let ret: i32 = ctx.ret();
    if ret <= 0 {
        return Ok(());
    }

    let (pid, _) = current_ids();
    unsafe {
        match NET_BYTES.get_ptr_mut(&pid) {
            Some(p) => {
                let totals = &mut *p;
                if sent {
                    totals.sent += ret as u64;
                } else {
                    totals.recv += ret as u64;
                }
            }
            None => {
                let totals = NetTotals {
                    sent: if sent { ret as u64 } else { 0 },
                    recv: if sent { 0 } else { ret as u64 },
                };
                let _ = NET_BYTES.insert(&pid, totals, 0);
            }
        }
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
