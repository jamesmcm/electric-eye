#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kretprobe, map, tracepoint},
    maps::{HashMap, RingBuf, lpm_trie::Key},
    programs::{RetProbeContext, TracePointContext},
};

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
pub const KIND_FILE_MMAP: u32 = 11;
pub const KIND_FILE_READ: u32 = 12;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;

const TCP_SYN_SENT: i32 = 2;
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
    pub writev_fd: u32,
    pub writev_vec: u32,
    pub writev_vlen: u32,
    pub pwrite64_fd: u32,
    pub pwrite64_count: u32,
    pub pwritev_fd: u32,
    pub pwritev_vec: u32,
    pub pwritev_vlen: u32,
    pub sendfile_out_fd: u32,
    pub sendfile_count: u32,
    pub copy_out_fd: u32,
    pub copy_len: u32,
    pub mmap_len: u32,
    pub mmap_prot: u32,
    pub mmap_flags: u32,
    pub mmap_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingOpen {
    pub path: u64,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingAccept {
    pub peer: u64,
    pub peer_len: u64,
    pub listen_fd: u32,
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
    pub flags: u32,
    pub fd: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
}

#[repr(C)]
pub struct RawWriteEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub fd: u32,
    pub count: u64,
    pub comm: [u8; 16],
}

#[repr(C)]
pub struct RawAcceptEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub fd: u32,
    pub listen_fd: u32,
    pub family: u32,
    pub port: u32,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
}

#[repr(C)]
pub struct RawFdEvent {
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub oldfd: u32,
    pub newfd: u32,
    pub comm: [u8; 16],
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
static PENDING_OPEN: HashMap<u32, PendingOpen> = HashMap::with_max_entries(8192, 0);

#[map]
static PENDING_ACCEPT: HashMap<u32, PendingAccept> = HashMap::with_max_entries(4096, 0);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathKey {
    pub bytes: [u8; 128],
}

#[map]
static READ_PREFIXES: aya_ebpf::maps::LpmTrie<PathKey, u8> = aya_ebpf::maps::LpmTrie::with_max_entries(4096, 0);

#[map]
static NET_BYTES: HashMap<u32, NetTotals> = HashMap::with_max_entries(16384, 0);

fn current_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

fn current_tid() -> u32 {
    bpf_get_current_pid_tgid() as u32
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

fn emit_path_record(p: *mut RawPathEvent, kind: u32, path_ptr: u64, flags: u32, fd: u32) -> bool {
    let Ok(comm) = current_comm() else {
        return false;
    };
    let (pid, uid) = current_ids();
    unsafe {
        (*p).kind = kind;
        (*p).pid = pid;
        (*p).uid = uid;
        (*p).flags = flags;
        (*p).fd = fd;
        (*p).comm = comm;
    }
    read_user_path(path_ptr, unsafe { &mut (*p).path }).is_ok()
}

fn reserve_path_event(kind: u32, path_ptr: u64, flags: u32, fd: u32) {
    let Some(mut slot) = EVENTS.reserve::<RawPathEvent>(0) else {
        return;
    };
    let p = slot.as_mut_ptr();
    if emit_path_record(p, kind, path_ptr, flags, fd) {
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

fn sensitive_read(path_ptr: u64) -> bool {
    if path_ptr == 0 {
        return false;
    }
    let mut bytes = [0u8; 128];
    if unsafe { bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut bytes) }.is_err() {
        return false;
    }
    if bytes[0] != b'/' {
        return false;
    }
    READ_PREFIXES
        .get(&Key::new(1024, PathKey { bytes }))
        .is_some()
}

fn push_write(kind: u32, fd: u64, count: u64) {
    if count == 0 || fd > u32::MAX as u64 {
        return;
    }
    let Ok(comm) = current_comm() else {
        return;
    };
    let (pid, uid) = current_ids();
    push_record(RawWriteEvent {
        kind,
        pid,
        uid,
        fd: fd as u32,
        count,
        comm,
    });
}

fn iovec_bytes(vec: u64, vlen: u64) -> u64 {
    if vec == 0 {
        return 0;
    }
    let count = vlen.min(64);
    let mut total = 0u64;
    let mut index = 0u64;
    while index < count {
        let len: u64 =
            match unsafe { bpf_probe_read_user((vec + index * 16 + 8) as *const u64) } {
                Ok(value) => value,
                Err(_) => break,
            };
        total = total.saturating_add(len);
        index += 1;
    }
    total
}

fn note_open(path: u64, flags: u32) {
    if path == 0 {
        return;
    }
    let key = current_tid();
    let _ = PENDING_OPEN.insert(&key, PendingOpen { path, flags }, 0);
}

fn finish_open(ctx: &TracePointContext, ret_offset: u32) -> Result<(), ()> {
    let key = current_tid();
    let Some(pending) = PENDING_OPEN.get_ptr(&key).map(|p| unsafe { *p }) else {
        return Ok(());
    };
    let _ = PENDING_OPEN.remove(&key);
    let ret: i64 = ctx_read(ctx, ret_offset as usize)?;
    if ret < 0 || ret > u32::MAX as i64 {
        return Ok(());
    }
    reserve_path_event(KIND_FILE_OPEN, pending.path, pending.flags, ret as u32);
    Ok(())
}

enum OpenKind {
    Openat,
    Openat2,
    Open,
}

fn try_finish_open(ctx: &TracePointContext, kind: OpenKind) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let ret_offset = match kind {
        OpenKind::Openat => offs.openat_ret,
        OpenKind::Openat2 => offs.openat2_ret,
        OpenKind::Open => offs.open_ret,
    };
    finish_open(ctx, ret_offset)
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

    let newstate: i32 = ctx_read(ctx, offs.newstate as usize)?;
    let kind = match newstate {
        TCP_SYN_SENT => KIND_CONNECT,
        TCP_LISTEN => KIND_LISTEN,
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
    let filename: u64 = ctx_read(ctx, offs.openat_filename as usize)?;
    if !writable_open(flags) {
        if sensitive_read(filename) {
            reserve_path_event(KIND_FILE_READ, filename, flags as u32, 0);
        }
        return Ok(());
    }
    note_open(filename, flags as u32);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
fn electric_eye_openat_exit(ctx: TracePointContext) -> i32 {
    match try_finish_open(&ctx, OpenKind::Openat) {
        Ok(()) => 0,
        Err(_) => 1,
    }
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
    let filename: u64 = ctx_read(ctx, offs.openat2_filename as usize)?;
    if !writable_open(flags as i32) {
        if sensitive_read(filename) {
            reserve_path_event(KIND_FILE_READ, filename, flags as u32, 0);
        }
        return Ok(());
    }
    note_open(filename, flags as u32);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat2")]
fn electric_eye_openat2_exit(ctx: TracePointContext) -> i32 {
    match try_finish_open(&ctx, OpenKind::Openat2) {
        Ok(()) => 0,
        Err(_) => 1,
    }
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
    let filename: u64 = ctx_read(ctx, offs.open_filename as usize)?;
    if !writable_open(flags) {
        if sensitive_read(filename) {
            reserve_path_event(KIND_FILE_READ, filename, flags as u32, 0);
        }
        return Ok(());
    }
    note_open(filename, flags as u32);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_exit_open")]
fn electric_eye_open_exit(ctx: TracePointContext) -> i32 {
    match try_finish_open(&ctx, OpenKind::Open) {
        Ok(()) => 0,
        Err(_) => 1,
    }
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
    reserve_path_event(KIND_FILE_UNLINK, pathname, 0, 0);
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
    reserve_path_event(KIND_FILE_UNLINK, pathname, 0, 0);
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
    reserve_path_event(KIND_FILE_UNLINK, pathname, 0, 0);
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

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
fn electric_eye_write(ctx: TracePointContext) -> i32 {
    match try_write(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_write(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let fd: u32 = ctx_read(ctx, offs.write_fd as usize)?;
    let count: u64 = ctx_read(ctx, offs.write_count as usize)?;
    push_write(KIND_FILE_WRITE, fd as u64, count);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_writev")]
fn electric_eye_writev(ctx: TracePointContext) -> i32 {
    match try_writev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_writev(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let fd: u64 = ctx_read(ctx, offs.writev_fd as usize)?;
    let vec: u64 = ctx_read(ctx, offs.writev_vec as usize)?;
    let vlen: u64 = ctx_read(ctx, offs.writev_vlen as usize)?;
    push_write(KIND_FILE_WRITE, fd, iovec_bytes(vec, vlen));
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwrite64")]
fn electric_eye_pwrite64(ctx: TracePointContext) -> i32 {
    match try_pwrite64(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pwrite64(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let fd: u64 = ctx_read(ctx, offs.pwrite64_fd as usize)?;
    let count: u64 = ctx_read(ctx, offs.pwrite64_count as usize)?;
    push_write(KIND_FILE_WRITE, fd, count);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwritev")]
fn electric_eye_pwritev(ctx: TracePointContext) -> i32 {
    match try_pwritev(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_pwritev(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let fd: u64 = ctx_read(ctx, offs.pwritev_fd as usize)?;
    let vec: u64 = ctx_read(ctx, offs.pwritev_vec as usize)?;
    let vlen: u64 = ctx_read(ctx, offs.pwritev_vlen as usize)?;
    push_write(KIND_FILE_WRITE, fd, iovec_bytes(vec, vlen));
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_sendfile64")]
fn electric_eye_sendfile(ctx: TracePointContext) -> i32 {
    match try_sendfile(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_sendfile(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let out_fd: u64 = ctx_read(ctx, offs.sendfile_out_fd as usize)?;
    let count: u64 = ctx_read(ctx, offs.sendfile_count as usize)?;
    push_write(KIND_FILE_WRITE, out_fd, count);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_copy_file_range")]
fn electric_eye_copy_file_range(ctx: TracePointContext) -> i32 {
    match try_copy_file_range(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_copy_file_range(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let out_fd: u64 = ctx_read(ctx, offs.copy_out_fd as usize)?;
    let len: u64 = ctx_read(ctx, offs.copy_len as usize)?;
    push_write(KIND_FILE_WRITE, out_fd, len);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
fn electric_eye_mmap(ctx: TracePointContext) -> i32 {
    match try_mmap(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_mmap(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let len: u64 = ctx_read(ctx, offs.mmap_len as usize)?;
    let prot: u64 = ctx_read(ctx, offs.mmap_prot as usize)?;
    let flags: u64 = ctx_read(ctx, offs.mmap_flags as usize)?;
    let fd: u64 = ctx_read(ctx, offs.mmap_fd as usize)?;
    const PROT_WRITE: u64 = 0x2;
    const MAP_SHARED: u64 = 0x1;
    if prot & PROT_WRITE == 0 || flags & MAP_SHARED == 0 || fd > i32::MAX as u64 {
        return Ok(());
    }
    push_write(KIND_FILE_MMAP, fd, len);
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_accept")]
fn electric_eye_accept_enter(ctx: TracePointContext) -> i32 {
    match note_accept(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_accept")]
fn electric_eye_accept_exit(ctx: TracePointContext) -> i32 {
    match finish_accept(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_accept4")]
fn electric_eye_accept4_enter(ctx: TracePointContext) -> i32 {
    match note_accept(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_accept4")]
fn electric_eye_accept4_exit(ctx: TracePointContext) -> i32 {
    match finish_accept(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn note_accept(ctx: &TracePointContext, accept4: bool) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let (fd_off, peer_off, len_off) = if accept4 {
        (offs.accept4_fd, offs.accept4_sockaddr, offs.accept4_addrlen)
    } else {
        (offs.accept_fd, offs.accept_sockaddr, offs.accept_addrlen)
    };
    let listen_fd: u32 = ctx_read(ctx, fd_off as usize)?;
    let peer: u64 = ctx_read(ctx, peer_off as usize)?;
    let peer_len: u64 = ctx_read(ctx, len_off as usize)?;
    let key = current_tid();
    let _ = PENDING_ACCEPT.insert(
        &key,
        PendingAccept {
            peer,
            peer_len,
            listen_fd,
        },
        0,
    );
    Ok(())
}

fn finish_accept(ctx: &TracePointContext, accept4: bool) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let key = current_tid();
    let Some(pending) = PENDING_ACCEPT.get_ptr(&key).map(|p| unsafe { *p }) else {
        return Ok(());
    };
    let _ = PENDING_ACCEPT.remove(&key);
    let ret_offset = if accept4 {
        offs.accept4_ret
    } else {
        offs.accept_ret
    };
    let ret: i64 = ctx_read(ctx, ret_offset as usize)?;
    if ret < 0 || ret > u32::MAX as i64 {
        return Ok(());
    }
    let (family, addr, port) = read_sockaddr(pending.peer);
    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();
    push_record(RawAcceptEvent {
        kind: KIND_ACCEPT,
        pid,
        uid,
        fd: ret as u32,
        listen_fd: pending.listen_fd,
        family,
        port: port as u32,
        addr,
        comm,
    });
    Ok(())
}

fn read_sockaddr(peer: u64) -> (u32, [u8; 16], u16) {
    let mut addr = [0u8; 16];
    if peer == 0 {
        return (0, addr, 0);
    }
    let family: u16 = match unsafe { bpf_probe_read_user(peer as *const u16) } {
        Ok(value) => value,
        Err(_) => return (0, addr, 0),
    };
    let port_be: u16 = match unsafe { bpf_probe_read_user((peer + 2) as *const u16) } {
        Ok(value) => value,
        Err(_) => return (0, addr, 0),
    };
    let port = u16::from_be(port_be);
    match family {
        AF_INET => {
            let raw: [u8; 4] = match unsafe { bpf_probe_read_user((peer + 4) as *const [u8; 4]) } {
                Ok(value) => value,
                Err(_) => return (0, [0; 16], 0),
            };
            addr[..4].copy_from_slice(&raw);
        }
        AF_INET6 => {
            addr = match unsafe { bpf_probe_read_user((peer + 8) as *const [u8; 16]) } {
                Ok(value) => value,
                Err(_) => return (0, [0; 16], 0),
            };
        }
        _ => return (0, [0; 16], 0),
    }
    (family as u32, addr, port)
}

#[tracepoint(category = "syscalls", name = "sys_enter_dup2")]
fn electric_eye_dup2(ctx: TracePointContext) -> i32 {
    match try_dup(&ctx, false) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_dup3")]
fn electric_eye_dup3(ctx: TracePointContext) -> i32 {
    match try_dup(&ctx, true) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_dup(ctx: &TracePointContext, dup3: bool) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let (old_off, new_off) = if dup3 {
        (offs.dup3_oldfd, offs.dup3_newfd)
    } else {
        (offs.dup2_oldfd, offs.dup2_newfd)
    };
    let oldfd: u32 = ctx_read(ctx, old_off as usize)?;
    let newfd: u32 = ctx_read(ctx, new_off as usize)?;
    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();
    push_record(RawFdEvent {
        kind: KIND_FD_DUP,
        pid,
        uid,
        oldfd,
        newfd,
        comm,
    });
    Ok(())
}

#[tracepoint(category = "syscalls", name = "sys_enter_close")]
fn electric_eye_close(ctx: TracePointContext) -> i32 {
    match try_close(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_close(ctx: &TracePointContext) -> Result<(), ()> {
    let offs: SyscallOffsets = unsafe { *SYSCALL_OFFSETS.get(&0).ok_or(())? };
    let fd: u32 = ctx_read(ctx, offs.close_fd as usize)?;
    let Ok(comm) = current_comm() else {
        return Ok(());
    };
    let (pid, uid) = current_ids();
    push_record(RawFdEvent {
        kind: KIND_FD_CLOSE,
        pid,
        uid,
        oldfd: fd,
        newfd: 0,
        comm,
    });
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
