#![no_std]
#![no_main]

#[path = "../../electric-eye-core/src/wire.rs"]
mod wire;
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
        bpf_get_ns_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_loop,
        bpf_probe_read_kernel, bpf_probe_read_kernel_buf, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, PerCpuArray, RingBuf,
    },
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use wire::*;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);
#[map]
static KERNEL_OFFSETS: HashMap<u32, KernelOffsets> = HashMap::with_max_entries(1, 0);
#[map]
static SOCK_OFFSETS: HashMap<u32, SockOffsets> = HashMap::with_max_entries(1, 0);
#[map]
static SYSCALL_OPS: HashMap<u64, u32> = HashMap::with_max_entries(64, 0);
#[map]
static PENDING: HashMap<u64, Record> = HashMap::with_max_entries(8192, 0);
#[map]
static READ_PREFIXES: LpmTrie<[u8; 128], u8> = LpmTrie::with_max_entries(4096, 0);
#[map]
static IGNORE_PREFIXES: LpmTrie<[u8; 128], u8> = LpmTrie::with_max_entries(4096, 0);
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_COUNT, 0);
#[map]
static DIR_SCRATCH: PerCpuArray<[u8; PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);
#[map]
static BUILD_SCRATCH: PerCpuArray<[u8; 1024]> = PerCpuArray::with_max_entries(1, 0);
#[map]
static PATH_SCRATCH: PerCpuArray<[u8; 1024]> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketMeta {
    id: u64,
    netns: u64,
    start_ns: u64,
    pid: u32,
    uid: u32,
    euid: u32,
    exec_id: u32,
    protocol: u32,
    comm: [u8; 16],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NetKey {
    tid: u64,
    kind: u32,
    pad: u32,
}
#[map]
static SOCKETS: HashMap<u64, SocketMeta> = HashMap::with_max_entries(32768, 0);
#[map]
static SOCKET_SEQUENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static NET_PENDING: HashMap<NetKey, Record> = HashMap::with_max_entries(8192, 0);
fn socket_record(sk: u64, e: &mut Record, protocol: u32, o: &KernelOffsets) -> Result<(), ()> {
    let common = sk + o.sock_common as u64;
    let family: u16 = read(common, o.skc_family)?;
    if family != 2 && family != 10 {
        return Err(());
    }
    e.family = family as u32;
    e.state = read::<u8>(common, o.skc_state)? as u32;
    e.protocol = protocol;
    e.local_port = read::<u16>(common, o.skc_num)? as u32;
    e.remote_port = u16::from_be(read::<u16>(common, o.skc_dport)?) as u32;
    if family == 2 {
        e.local_addr[..4].copy_from_slice(&read::<[u8; 4]>(common, o.skc_rcv_saddr)?);
        e.addr[..4].copy_from_slice(&read::<[u8; 4]>(common, o.skc_daddr)?);
    } else {
        e.local_addr = read(common, o.skc_v6_rcv_saddr)?;
        e.addr = read(common, o.skc_v6_daddr)?;
    }
    e.netns = read::<u64>(common, o.skc_net)
        .and_then(|net| read::<u32>(net, o.net_inum))
        .unwrap_or(0) as u64;
    if unsafe { SOCKETS.get(&sk) }.is_none() {
        let sequence = SOCKET_SEQUENCE.get_ptr_mut(0).ok_or(())?;
        let cpu = unsafe { bpf_get_smp_processor_id() } as u64;
        if cpu > 65535 || unsafe { *sequence } >= 0x0000_ffff_ffff_ffff {
            return Err(());
        }
        let id = unsafe {
            *sequence += 1;
            (*sequence << 16) | cpu
        };
        let meta = SocketMeta {
            id,
            netns: e.netns,
            start_ns: e.start_ns,
            pid: e.pid,
            uid: e.uid,
            euid: e.euid,
            exec_id: e.exec_id,
            protocol,
            comm: e.comm,
        };
        if SOCKETS.insert(&sk, meta, 1).is_err() && unsafe { SOCKETS.get(&sk) }.is_none() {
            dropped(DROP_PENDING);
            return Err(());
        }
    }
    e.socket_id = unsafe { SOCKETS.get(&sk).ok_or(())?.id };
    Ok(())
}
fn socket_fd(fd: u32, e: &mut Record, o: &KernelOffsets) -> Result<(), ()> {
    let file = fd_file(fd, o)?;
    let inode: u64 = read(file, o.file_inode)?;
    let mode: u16 = read(inode, o.inode_mode)?;
    if mode & 0o170000 != 0o140000 {
        return Err(());
    }
    let socket: u64 = read(file, o.file_private_data)?;
    let kind: i16 = read(socket, o.socket_type)?;
    let protocol = match kind {
        1 => 6,
        2 => 17,
        _ => return Err(()),
    };
    let sk: u64 = read(socket, o.socket_sk)?;
    socket_record(sk, e, protocol, o)
}
fn saved_socket(sk: u64, e: &mut Record, o: &KernelOffsets) -> Result<(), ()> {
    let meta = unsafe { SOCKETS.get(&sk).copied().ok_or(())? };
    unsafe {
        bpf_probe_read_kernel_buf(
            (&Record::ZERO as *const Record).cast::<u8>(),
            core::slice::from_raw_parts_mut(
                (e as *mut Record).cast::<u8>(),
                core::mem::size_of::<Record>(),
            ),
        )
        .map_err(|_| ())?;
    }
    e.pid = meta.pid;
    e.start_ns = meta.start_ns;
    e.uid = meta.uid;
    e.euid = meta.euid;
    e.exec_id = meta.exec_id;
    e.comm = meta.comm;
    e.ts_ns = unsafe { bpf_ktime_get_boot_ns() };
    socket_record(sk, e, meta.protocol, o)
}
#[kprobe]
fn electric_eye_socket_free(ctx: ProbeContext) -> i32 {
    let _ = (|| -> Result<(), ()> {
        let sk: u64 = ctx.arg(0).ok_or(())?;
        let o = offsets()?;
        if unsafe { SOCKETS.get(&sk) }.is_none() {
            return Ok(());
        }
        if let Some(mut slot) = EVENTS.reserve::<Record>(0) {
            let e = unsafe { &mut *slot.as_mut_ptr() };
            if saved_socket(sk, e, o).is_ok() {
                e.kind = NET_CLOSE;
                slot.submit(0);
            } else {
                slot.discard(0);
            }
        } else {
            dropped(DROP_RING);
        }
        let _ = SOCKETS.remove(&sk);
        Ok(())
    })();
    0
}
#[kprobe]
fn electric_eye_socket_release(ctx: ProbeContext) -> i32 {
    let _ = (|| -> Result<(), ()> {
        let socket: u64 = ctx.arg(0).ok_or(())?;
        let o = offsets()?;
        let sk: u64 = read(socket, o.socket_sk)?;
        if unsafe { SOCKETS.get(&sk) }.is_none() {
            return Ok(());
        }
        if let Some(mut slot) = EVENTS.reserve::<Record>(0) {
            let e = unsafe { &mut *slot.as_mut_ptr() };
            if saved_socket(sk, e, o).is_ok() {
                e.kind = NET_CLOSE;
                slot.submit(0);
            } else {
                slot.discard(0);
            }
        } else {
            dropped(DROP_RING);
        }
        let _ = SOCKETS.remove(&sk);
        Ok(())
    })();
    0
}
#[kprobe]
fn electric_eye_tcp_sent_enter(ctx: ProbeContext) -> i32 {
    net_enter(&ctx, SENT, 6);
    0
}
#[kprobe]
fn electric_eye_tcp_recv_enter(ctx: ProbeContext) -> i32 {
    net_enter(&ctx, RECEIVED, 6);
    0
}
#[kprobe]
fn electric_eye_udp_sent_enter(ctx: ProbeContext) -> i32 {
    net_enter(&ctx, SENT, 17);
    0
}
#[kprobe]
fn electric_eye_udp_recv_enter(ctx: ProbeContext) -> i32 {
    net_enter(&ctx, RECEIVED, 17);
    0
}
fn net_enter(ctx: &ProbeContext, kind: u32, protocol: u32) {
    let _ = (|| -> Result<(), ()> {
        let o = offsets()?;
        if !capture_current(o) {
            return Ok(());
        }
        let sk: u64 = ctx.arg(0).ok_or(())?;
        let msg: u64 = ctx.arg(1).ok_or(())?;
        let Some(mut slot) = EVENTS.reserve::<Record>(0) else {
            dropped(DROP_RING);
            return Ok(());
        };
        let e = unsafe { &mut *slot.as_mut_ptr() };
        if !fill_identity(e, o) || socket_record(sk, e, protocol, o).is_err() {
            slot.discard(0);
            return Ok(());
        }
        e.kind = kind;
        e.count = msg;
        e.result = sk as i64;
        if protocol == 17 && kind == SENT {
            kernel_peer(msg, e, o);
        }
        let key = NetKey {
            tid: bpf_get_current_pid_tgid(),
            kind,
            pad: 0,
        };
        if NET_PENDING.insert(&key, e, 0).is_err() {
            dropped(DROP_PENDING);
        }
        slot.discard(0);
        Ok(())
    })();
}
#[kretprobe]
fn electric_eye_udp_skb(ctx: RetProbeContext) -> i32 {
    let _ = (|| -> Result<(), ()> {
        let skb: u64 = ctx.ret();
        if skb == 0 || skb > u64::MAX - 4096 {
            return Ok(());
        }
        let key = NetKey {
            tid: bpf_get_current_pid_tgid(),
            kind: RECEIVED,
            pad: 0,
        };
        let Some(ptr) = NET_PENDING.get_ptr_mut(&key) else {
            return Ok(());
        };
        let e = unsafe { &mut *ptr };
        if e.protocol != 17 {
            return Ok(());
        }
        let o = offsets()?;
        let head: u64 = read(skb, o.skb_head)?;
        let network: u16 = read(skb, o.skb_network)?;
        let transport: u16 = read(skb, o.skb_transport)?;
        e.remote_port = u16::from_be(read::<u16>(head + transport as u64, 0)?) as u32;
        if e.family == 2 {
            e.addr[..4].copy_from_slice(&read::<[u8; 4]>(head + network as u64, 12)?);
        } else {
            e.addr = read(head + network as u64, 8)?;
        }
        Ok(())
    })();
    0
}
fn kernel_peer(msg: u64, e: &mut Record, o: &KernelOffsets) {
    if let Ok(peer) = read::<u64>(msg, o.msg_name) {
        if peer != 0 {
            if let Ok(family) = read::<u16>(peer, 0) {
                if family as u32 == e.family {
                    e.remote_port = u16::from_be(read::<u16>(peer, 2).unwrap_or(0)) as u32;
                    if family == 2 {
                        e.addr[..4].copy_from_slice(&read::<[u8; 4]>(peer, 4).unwrap_or([0; 4]));
                    } else {
                        e.addr = read(peer, 8).unwrap_or([0; 16]);
                    }
                }
            }
        }
    }
}

fn dropped(reason: u32) {
    if let Some(p) = DROPPED.get_ptr_mut(reason) {
        unsafe {
            *p += 1;
        }
    }
}
fn offsets() -> Result<&'static KernelOffsets, ()> {
    unsafe { KERNEL_OFFSETS.get(&0).ok_or(()) }
}
fn read<T: Copy>(base: u64, offset: u32) -> Result<T, ()> {
    if base == 0 {
        return Err(());
    }
    unsafe { bpf_probe_read_kernel((base + offset as u64) as *const T).map_err(|_| ()) }
}
fn task() -> u64 {
    unsafe { bpf_get_current_task() }
}
fn fd_file(fd: u32, o: &KernelOffsets) -> Result<u64, ()> {
    let files: u64 = read(task(), o.task_files)?;
    let fdt: u64 = read(files, o.files_fdt)?;
    let max: u32 = read(fdt, o.fdt_max_fds)?;
    if fd >= max || fd > 1_048_576 {
        return Err(());
    }
    let array: u64 = read(fdt, o.fdt_fd)?;
    let file: u64 = read(array, fd * 8)?;
    if file == 0 {
        Err(())
    } else {
        Ok(file)
    }
}

struct Walk {
    mnt: u64,
    dentry: u64,
    root_mnt: u64,
    root_dentry: u64,
    offsets: *const KernelOffsets,
    pos: usize,
    complete: bool,
}
unsafe extern "C" fn path_component(_index: u32, context: *mut core::ffi::c_void) -> i64 {
    let walk = &mut *context.cast::<Walk>();
    match component(walk) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(()) => 1,
    }
}
fn component(w: &mut Walk) -> Result<bool, ()> {
    let o = unsafe { &*w.offsets };
    if w.mnt == w.root_mnt && w.dentry == w.root_dentry {
        w.complete = true;
        return Ok(true);
    }
    let mnt_root: u64 = read(w.mnt, o.vfsmount_root)?;
    if w.dentry == mnt_root {
        let mount = w.mnt.checked_sub(o.mount_mnt as u64).ok_or(())?;
        let parent: u64 = read(mount, o.mount_parent)?;
        if parent == mount {
            return Err(());
        }
        w.dentry = read(mount, o.mount_mountpoint)?;
        w.mnt = parent + o.mount_mnt as u64;
        return Ok(false);
    }
    let parent: u64 = read(w.dentry, o.dentry_parent)?;
    if parent == w.dentry {
        return Err(());
    }
    let len: u32 = read(w.dentry, o.dentry_name + o.qstr_len)?;
    let name: u64 = read(w.dentry, o.dentry_name + o.qstr_name)?;
    let len = len as usize;
    if len == 0 || len > 255 || w.pos > PATH_LEN - 1 || len + 1 > w.pos {
        return Err(());
    }
    let pos = unsafe { core::ptr::read_volatile(&w.pos) }.wrapping_sub(len) & (PATH_LEN - 1);
    // Spare scratch capacity gives the verifier independent bounds for the
    // variable destination offset and name length.
    let scratch = unsafe { &mut *PATH_SCRATCH.get_ptr_mut(0).ok_or(())? };
    unsafe {
        bpf_probe_read_kernel_buf(
            name as *const u8,
            core::slice::from_raw_parts_mut(scratch.as_mut_ptr().add(pos), len),
        )
        .map_err(|_| ())?;
    }
    w.pos = pos - 1;
    unsafe {
        *scratch.get_unchecked_mut(w.pos & (PATH_LEN - 1)) = b'/';
    }
    w.dentry = parent;
    Ok(false)
}
/// Walk resolved dentries across mount points in the caller's namespace.
/// bpf_loop bounds work without multiplying verifier states by path depth.
#[inline(never)]
fn kernel_path(
    mnt: u64,
    dentry: u64,
    out: &mut [u8; PATH_LEN],
    o: &KernelOffsets,
) -> Result<usize, ()> {
    let fs: u64 = read(task(), o.task_fs)?;
    let mut walk = Walk {
        mnt,
        dentry,
        root_mnt: read(fs, o.fs_root + o.path_mnt)?,
        root_dentry: read(fs, o.fs_root + o.path_dentry)?,
        offsets: o,
        pos: PATH_LEN - 1,
        complete: false,
    };
    let scratch = unsafe { &mut *PATH_SCRATCH.get_ptr_mut(0).ok_or(())? };
    scratch[PATH_LEN - 1] = 0;
    if unsafe {
        bpf_loop(
            80,
            path_component as *mut core::ffi::c_void,
            (&mut walk as *mut Walk).cast(),
            0,
        )
    } < 0
        || !walk.complete
    {
        return Err(());
    }
    if walk.pos == PATH_LEN - 1 {
        walk.pos -= 1;
        unsafe {
            *scratch.get_unchecked_mut(walk.pos & (PATH_LEN - 1)) = b'/';
        }
    }
    let pos = walk.pos & (PATH_LEN - 1);
    unsafe {
        bpf_probe_read_kernel_buf(
            scratch.as_ptr().add(pos),
            core::slice::from_raw_parts_mut(out.as_mut_ptr(), PATH_LEN - pos),
        )
        .map_err(|_| ())?;
    }
    Ok(PATH_LEN - pos - 1)
}
fn path_at(path: u64, out: &mut [u8; PATH_LEN], o: &KernelOffsets) -> Result<usize, ()> {
    kernel_path(read(path, o.path_mnt)?, read(path, o.path_dentry)?, out, o)
}
fn file_path(file: u64, out: &mut [u8; PATH_LEN], o: &KernelOffsets) -> Result<usize, ()> {
    path_at(file + o.file_path as u64, out, o)
}
fn capture_current(o: &KernelOffsets) -> bool {
    let mut ns = aya_ebpf::bindings::bpf_pidns_info { pid: 0, tgid: 0 };
    (unsafe {
        bpf_get_ns_current_pid_tgid(
            o.own_ns_dev,
            o.own_ns_ino,
            &mut ns,
            core::mem::size_of_val(&ns) as u32,
        ) == 0
    }) && ns.tgid != o.own_pid
}
fn identity(e: &mut Record, o: &KernelOffsets) -> Result<bool, ()> {
    unsafe {
        bpf_probe_read_kernel_buf(
            (&Record::ZERO as *const Record).cast::<u8>(),
            core::slice::from_raw_parts_mut(
                (e as *mut Record).cast::<u8>(),
                core::mem::size_of::<Record>(),
            ),
        )
        .map_err(|_| ())?;
    }
    let mut ns = aya_ebpf::bindings::bpf_pidns_info { pid: 0, tgid: 0 };
    if unsafe {
        bpf_get_ns_current_pid_tgid(
            o.own_ns_dev,
            o.own_ns_ino,
            &mut ns,
            core::mem::size_of_val(&ns) as u32,
        )
    } != 0
    {
        return Ok(false);
    }
    e.pid = ns.tgid;
    if e.pid == o.own_pid {
        return Ok(false);
    }
    e.uid = bpf_get_current_uid_gid() as u32;
    let leader: u64 = read(task(), o.task_group_leader)?;
    e.start_ns = read(leader, o.task_start_boottime)?;
    unsafe {
        bpf_probe_read_kernel_buf((leader + o.task_comm as u64) as *const u8, &mut e.comm)
            .map_err(|_| ())?;
    }
    let parent_task: u64 = read(leader, o.task_real_parent)?;
    let parent: u64 = read(parent_task, o.task_group_leader).unwrap_or(parent_task);
    e.ppid = namespace_pid(parent, o).unwrap_or(0);
    e.parent_start_ns = read(parent, o.task_start_boottime).unwrap_or(0);
    e.exec_id = read(leader, o.task_exec_id).unwrap_or(0);
    if let Ok(cred) = read::<u64>(task(), o.task_cred) {
        e.uid = read(cred, o.cred_uid).unwrap_or(e.uid);
        e.euid = read(cred, o.cred_euid).unwrap_or(e.uid);
    }
    let _ = unsafe {
        bpf_probe_read_kernel_buf(
            (parent + o.task_comm as u64) as *const u8,
            &mut e.parent_comm,
        )
    };
    e.ts_ns = unsafe { bpf_ktime_get_boot_ns() };
    if let Ok(mm) = read::<u64>(task(), o.task_mm) {
        if let Ok(exe) = read::<u64>(mm, o.mm_exe_file) {
            let _ = file_path(exe, &mut e.exe, o);
            if let Ok(inode) = read::<u64>(exe, o.file_inode) {
                e.exe_inode = read(inode, o.inode_ino).unwrap_or(0);
                if let Ok(sb) = read::<u64>(inode, o.inode_sb) {
                    e.exe_dev = read(sb, o.sb_dev).unwrap_or(0);
                }
            }
        }
    }
    Ok(true)
}
fn namespace_pid(t: u64, o: &KernelOffsets) -> Result<u32, ()> {
    let leader: u64 = read(t, o.task_group_leader)?;
    let pid: u64 = read(leader, o.task_thread_pid)?;
    let level: u32 = read(pid, o.pid_level)?;
    for i in 0..32u32 {
        if i > level {
            break;
        }
        let upid = pid + o.pid_numbers as u64 + i as u64 * 16;
        let ns: u64 = read(upid, o.upid_ns)?;
        let inum: u32 = read(ns, o.pid_ns_inum)?;
        if inum as u64 == o.own_ns_ino {
            return read(upid, o.upid_nr);
        }
    }
    Err(())
}
struct CgroupWalk {
    node: u64,
    pos: usize,
    complete: bool,
    offsets: *const KernelOffsets,
}
unsafe extern "C" fn cgroup_component(_: u32, ctx: *mut core::ffi::c_void) -> i64 {
    let w = &mut *ctx.cast::<CgroupWalk>();
    let o = &*w.offsets;
    let result = (|| -> Result<bool, ()> {
        let parent: u64 = read(w.node, o.kn_parent)?;
        if parent == 0 {
            w.complete = true;
            return Ok(true);
        }
        let name: u64 = read(w.node, o.kn_name)?;
        let buf = &mut *DIR_SCRATCH.get_ptr_mut(0).ok_or(())?;
        let n = aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes(name as *const u8, buf)
            .map_err(|_| ())?
            .len();
        if n == 0 || n > 255 || w.pos > 255 || n + 1 > w.pos {
            return Err(());
        }
        let pos = core::ptr::read_volatile(&w.pos).wrapping_sub(n) & 255;
        let scratch = &mut *PATH_SCRATCH.get_ptr_mut(0).ok_or(())?;
        bpf_probe_read_kernel_buf(
            buf.as_ptr(),
            core::slice::from_raw_parts_mut(scratch.as_mut_ptr().add(pos), n),
        )
        .map_err(|_| ())?;
        w.pos = pos - 1;
        *scratch.get_unchecked_mut(w.pos & 255) = b'/';
        w.node = parent;
        Ok(false)
    })();
    match result {
        Ok(false) => 0,
        _ => 1,
    }
}
fn metadata(e: &mut Record, t: u64, o: &KernelOffsets) {
    if let Ok(fs) = read::<u64>(t, o.task_fs) {
        if path_at(fs + o.fs_pwd as u64, &mut e.path, o).is_ok() {
            e.metadata_flags |= 1;
        }
    }
    if let Ok(mm) = read::<u64>(t, o.task_mm) {
        if let (Ok(start), Ok(end)) = (
            read::<u64>(mm, o.mm_arg_start),
            read::<u64>(mm, o.mm_arg_end),
        ) {
            let size = end.saturating_sub(start);
            let n = size.min(PATH_LEN as u64) as usize;
            if n > 0 && n <= PATH_LEN {
                if unsafe { bpf_probe_read_user(start as *const [u8; 1]) }.is_ok() {
                    let dst = unsafe { core::slice::from_raw_parts_mut(e.path2.as_mut_ptr(), n) };
                    if unsafe {
                        aya_ebpf::helpers::bpf_probe_read_user_buf(start as *const u8, dst)
                    }
                    .is_ok()
                    {
                        e.metadata_flags |= 2;
                        e.count = n as u64;
                        if size > PATH_LEN as u64 {
                            e.metadata_flags |= 8;
                        }
                    }
                }
            }
        }
    }
    if let Ok(css) = read::<u64>(t, o.task_cgroups) {
        if let Ok(group) = read::<u64>(css, o.css_dfl_cgrp) {
            if let Ok(node) = read::<u64>(group, o.cgroup_kn) {
                let mut w = CgroupWalk {
                    node,
                    pos: 255,
                    complete: false,
                    offsets: o,
                };
                if let Some(scratch) = PATH_SCRATCH.get_ptr_mut(0) {
                    unsafe {
                        (*scratch)[255] = 0;
                        bpf_loop(
                            64,
                            cgroup_component as *mut core::ffi::c_void,
                            (&mut w as *mut CgroupWalk).cast(),
                            0,
                        );
                        if w.complete {
                            if w.pos == 255 {
                                w.pos = 254;
                                (*scratch)[254] = b'/';
                            }
                            let pos = w.pos & 255;
                            if bpf_probe_read_kernel_buf(
                                (*scratch).as_ptr().add(pos),
                                core::slice::from_raw_parts_mut(e.cgroup.as_mut_ptr(), 256 - pos),
                            )
                            .is_ok()
                            {
                                e.metadata_flags |= 4;
                            }
                        }
                    }
                }
            }
        }
    }
}
#[kprobe]
fn electric_eye_fork(ctx: ProbeContext) -> i32 {
    let _ = (|| -> Result<(), ()> {
        let o = offsets()?;
        if !capture_current(o) {
            return Ok(());
        }
        let child: u64 = ctx.arg(0).ok_or(())?;
        let tid: u32 = read(child, o.task_pid)?;
        let tgid: u32 = read(child, o.task_tgid)?;
        if tid != tgid {
            return Ok(());
        }
        let Some(mut slot) = EVENTS.reserve::<Record>(0) else {
            dropped(DROP_RING);
            return Ok(());
        };
        let e = unsafe { &mut *slot.as_mut_ptr() };
        if !fill_identity(e, &o) {
            slot.discard(0);
            return Ok(());
        }
        e.ppid = e.pid;
        e.parent_start_ns = e.start_ns;
        e.pid = namespace_pid(child, &o).unwrap_or(0);
        e.start_ns = read(child, o.task_start_boottime).unwrap_or(0);
        if e.pid == 0 || e.start_ns == 0 {
            slot.discard(0);
            return Ok(());
        }
        e.kind = FORK;
        metadata(e, child, &o);
        slot.submit(0);
        Ok(())
    })();
    0
}
fn fill_identity(e: &mut Record, o: &KernelOffsets) -> bool {
    match identity(e, o) {
        Ok(captured) => captured,
        Err(()) => {
            dropped(DROP_IDENTITY);
            false
        }
    }
}

fn file_identity(fd: u32, e: &mut Record, o: &KernelOffsets) {
    let Ok(file) = fd_file(fd, o) else {
        return;
    };
    let Ok(inode) = read::<u64>(file, o.file_inode) else {
        return;
    };
    e.file_inode = read::<u64>(inode, o.inode_ino).unwrap_or(0);
    if let Ok(sb) = read::<u64>(inode, o.inode_sb) {
        e.file_dev = read::<u32>(sb, o.sb_dev).unwrap_or(0);
    }
}
fn copy_path(dst: &mut [u8; PATH_LEN], src: &[u8; PATH_LEN]) {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), PATH_LEN);
    }
}
/// The sys_enter tracepoint runs before the syscall copies its pathname from
/// user memory. A page that is not resident there makes probe_read_user_str
/// fail without faulting it in. By sys_exit the kernel has read the path, so a
/// retry usually recovers exactly the failed-open path we want to explain.
fn retry_open_path(e: &mut Record, o: &KernelOffsets) {
    if e.kind != OPEN || e.path_resolution != PATH_UNRESOLVED || e.path_ptr == 0 {
        return;
    }
    let retried = syscall_path(e.path_ptr, e.dirfd, &mut e.path2, o);
    if retried != PATH_UNRESOLVED {
        copy_path(&mut e.path, &e.path2);
        e.path_resolution = retried;
    } else if e.path2[0] != 0 {
        // Keep a relative name as a lexical fallback rather than losing it.
        copy_path(&mut e.path, &e.path2);
        e.path_resolution = PATH_LEXICAL;
    }
}
fn read_user_path(ptr: u64, out: &mut [u8; PATH_LEN]) -> Result<usize, ()> {
    out.fill(0);
    let bytes = unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, out).map_err(|_| ())? };
    // A full buffer can be truncated; do not claim an exact path.
    if bytes.len() >= PATH_LEN - 1 {
        return Err(());
    }
    Ok(bytes.len())
}
#[inline(never)]
fn syscall_path(ptr: u64, dirfd: i32, out: &mut [u8; PATH_LEN], o: &KernelOffsets) -> u32 {
    let Ok(name_len) = read_user_path(ptr, out) else {
        out.fill(0);
        return PATH_UNRESOLVED;
    };
    if out[0] == b'/' {
        return PATH_LEXICAL;
    }
    let Some(temp) = DIR_SCRATCH.get_ptr_mut(0) else {
        return PATH_UNRESOLVED;
    };
    let temp = unsafe { &mut *temp };
    let result = if dirfd == -100 {
        read::<u64>(task(), o.task_fs).and_then(|fs| path_at(fs + o.fs_pwd as u64, temp, o))
    } else if dirfd >= 0 {
        fd_file(dirfd as u32, o).and_then(|file| file_path(file, temp, o))
    } else {
        Err(())
    };
    let Ok(mut base_len) = result else {
        return PATH_UNRESOLVED;
    };
    if base_len + name_len + 2 >= PATH_LEN {
        return PATH_UNRESOLVED;
    }
    if base_len == 1 {
        base_len = 0;
    }
    let Some(build) = BUILD_SCRATCH.get_ptr_mut(0) else {
        return PATH_UNRESOLVED;
    };
    let build = unsafe { &mut *build };
    let result = (|| -> Result<(), ()> {
        unsafe {
            bpf_probe_read_kernel_buf([0u8; PATH_LEN].as_ptr(), &mut build[..PATH_LEN])
                .map_err(|_| ())?;
        }
        if base_len > 0 {
            unsafe {
                bpf_probe_read_kernel_buf(
                    temp.as_ptr(),
                    core::slice::from_raw_parts_mut(build.as_mut_ptr(), base_len),
                )
                .map_err(|_| ())?;
            }
        }
        let index = base_len & (PATH_LEN - 1);
        unsafe {
            *build.get_unchecked_mut(index) = b'/';
        }
        let name =
            unsafe { core::slice::from_raw_parts_mut(build.as_mut_ptr().add(index + 1), PATH_LEN) };
        let actual =
            unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, name).map_err(|_| ())? }.len();
        if index + actual + 2 >= PATH_LEN {
            return Err(());
        }
        unsafe {
            bpf_probe_read_kernel_buf(build.as_ptr(), out).map_err(|_| ())?;
        }
        Ok(())
    })();
    if result.is_ok() {
        PATH_LEXICAL
    } else {
        PATH_UNRESOLVED
    }
}
fn sensitive(path: &[u8; PATH_LEN]) -> bool {
    let mut key = [0u8; 128];
    key.copy_from_slice(&path[..128]);
    READ_PREFIXES.get(&Key::new(1024, key)).is_some()
}
fn ignored(path: &[u8; PATH_LEN]) -> bool {
    let mut key = [0u8; 128];
    key.copy_from_slice(&path[..128]);
    IGNORE_PREFIXES.get(&Key::new(1024, key)).is_some()
}

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
fn electric_eye_sys_enter(ctx: TracePointContext) -> i32 {
    let _ = enter(&ctx);
    0
}
fn enter(ctx: &TracePointContext) -> Result<(), ()> {
    let o = offsets()?;
    if !capture_current(o) {
        return Ok(());
    }
    let id: u64 = unsafe { ctx.read_at(o.enter_id as usize).map_err(|_| ())? };
    let Some(op) = (unsafe { SYSCALL_OPS.get(&id).copied() }) else {
        return Ok(());
    };
    let args: [u64; 6] = unsafe { ctx.read_at(o.enter_args as usize).map_err(|_| ())? };
    let Some(mut slot) = EVENTS.reserve::<Record>(0) else {
        dropped(DROP_RING);
        return Ok(());
    };
    let e = unsafe { &mut *slot.as_mut_ptr() };
    if !fill_identity(e, &o) {
        slot.discard(0);
        return Ok(());
    }
    match op {
        OP_OPEN | OP_OPENAT | OP_OPENAT2 | OP_CREAT => {
            e.kind = OPEN;
            let (ptr, dirfd, flags) = if op == OP_CREAT {
                (args[0], -100, 0o1101)
            } else if op == OP_OPEN {
                (args[0], -100, args[1])
            } else if op == OP_OPENAT {
                (args[1], args[0] as i32, args[2])
            } else {
                (args[1], args[0] as i32, unsafe {
                    bpf_probe_read_user(args[2] as *const u64).unwrap_or(0)
                })
            };
            e.flags = flags as u32;
            e.path_ptr = ptr;
            e.dirfd = dirfd;
            e.path_resolution = syscall_path(ptr, dirfd, &mut e.path, &o);
        }
        OP_TRUNCATE | OP_FTRUNCATE => {
            e.kind = OPEN;
            e.flags = FLAG_TRUNCATE_SYSCALL | 0o1001;
            if op == OP_TRUNCATE {
                e.path_ptr = args[0];
                e.dirfd = -100;
                e.path_resolution = syscall_path(args[0], -100, &mut e.path, o);
            } else {
                e.fd = args[0] as u32;
                // ftruncate has no dirfd; keep the placeholder fd-oriented.
                e.dirfd = -1;
                if fd_file(e.fd, o)
                    .and_then(|f| file_path(f, &mut e.path, o))
                    .is_ok()
                {
                    e.path_resolution = PATH_KERNEL;
                } else {
                    file_identity(e.fd, e, o);
                }
            }
        }
        OP_WRITE | OP_SENDFILE | OP_COPY | OP_MMAP => {
            e.kind = if op == OP_MMAP { MMAP } else { WRITE };
            let fd = if op == OP_COPY {
                args[2]
            } else if op == OP_MMAP {
                args[4]
            } else {
                args[0]
            };
            if op == OP_MMAP && (args[2] & 2 == 0 || args[3] & 1 == 0) {
                slot.discard(0);
                return Ok(());
            }
            if fd > i32::MAX as u64 {
                slot.discard(0);
                return Ok(());
            }
            e.fd = fd as u32;
            let regular = fd_file(e.fd, &o)
                .and_then(|f| read::<u64>(f, o.file_inode))
                .and_then(|inode| read::<u16>(inode, o.inode_mode))
                .is_ok_and(|mode| mode & 0o170000 == 0o100000);
            if !regular {
                slot.discard(0);
                return Ok(());
            }
            e.count = if op == OP_MMAP { args[1] } else { 0 };
            if fd_file(e.fd, &o)
                .and_then(|f| file_path(f, &mut e.path, &o))
                .is_ok()
            {
                e.path_resolution = PATH_KERNEL;
            } else {
                file_identity(e.fd, e, o);
            }
        }
        OP_UNLINK | OP_UNLINKAT => {
            e.kind = UNLINK;
            e.path_resolution = if op == OP_UNLINK {
                syscall_path(args[0], -100, &mut e.path, &o)
            } else {
                syscall_path(args[1], args[0] as i32, &mut e.path, &o)
            };
        }
        OP_RENAME | OP_RENAMEAT => {
            e.kind = RENAME;
            let (p1, d1, p2, d2) = if op == OP_RENAME {
                (args[0], -100, args[1], -100)
            } else {
                (args[1], args[0] as i32, args[3], args[2] as i32)
            };
            e.path_resolution = syscall_path(p1, d1, &mut e.path, &o);
            e.path2_resolution = syscall_path(p2, d2, &mut e.path2, &o);
        }
        OP_SOERROR => {
            if args[1] != 1 || args[2] != 4 {
                slot.discard(0);
                return Ok(());
            }
            e.kind = NET_RESULT;
            e.fd = args[0] as u32;
            e.flags = FLAG_SO_ERROR;
            e.count = args[3];
        }
        OP_SOCKET => {
            e.kind = SOCKET;
        }
        OP_BIND | OP_CONNECT => {
            e.kind = if op == OP_BIND { BIND } else { NET_RESULT };
            e.fd = args[0] as u32;
            let _ = socket_fd(e.fd, e, o);
            if op == OP_CONNECT {
                read_peer(args[1], e);
            }
        }
        OP_ACCEPT => {
            e.kind = ACCEPT;
            e.fd = args[0] as u32;
            e.count = args[1];
            e.flags = 0;
        }
        _ => {
            slot.discard(0);
            return Ok(());
        }
    }
    let key = bpf_get_current_pid_tgid();
    if PENDING.insert(&key, e, 0).is_err() {
        dropped(DROP_PENDING);
    }
    slot.discard(0);
    Ok(())
}
#[tracepoint(category = "raw_syscalls", name = "sys_exit")]
fn electric_eye_sys_exit(ctx: TracePointContext) -> i32 {
    let _ = finish(&ctx);
    0
}
fn finish(ctx: &TracePointContext) -> Result<(), ()> {
    let key = bpf_get_current_pid_tgid();
    let Some(p) = PENDING.get_ptr_mut(&key) else {
        return Ok(());
    };
    let result = finish_pending(ctx, unsafe { &mut *p });
    let _ = PENDING.remove(&key);
    result
}
fn finish_pending(ctx: &TracePointContext, e: &mut Record) -> Result<(), ()> {
    let o = offsets()?;
    let ret: i64 = unsafe { ctx.read_at(o.exit_ret as usize).map_err(|_| ())? };
    e.result = ret;
    e.ts_ns = unsafe { bpf_ktime_get_boot_ns() };
    retry_open_path(e, &o);
    if e.kind == NET_RESULT && e.flags == FLAG_SO_ERROR {
        if ret < 0 {
            return Ok(());
        }
        let error: i32 = unsafe { bpf_probe_read_user(e.count as *const i32).map_err(|_| ())? };
        e.result = -(error as i64);
    }
    if matches!(e.kind, SOCKET | BIND | NET_RESULT) {
        if e.kind == SOCKET {
            if ret < 0 {
                return Ok(());
            }
            e.fd = ret as u32;
        }
        if socket_fd(e.fd, e, o).is_ok() {
            submit(e);
        }
        return Ok(());
    }
    if ret < 0 {
        // Restart pseudo-errors are kernel control flow, not completed attempts.
        if matches!(ret, -512 | -513 | -514 | -516) || e.kind == ACCEPT {
            return Ok(());
        }
        if e.kind == OPEN && e.flags & 3 == 0 && e.flags & (0o100 | 0o1000) == 0 {
            if !sensitive(&e.path) {
                return Ok(());
            }
            e.kind = READ;
        }
        e.count = 0;
        submit(e);
        return Ok(());
    }
    if e.kind == OPEN && e.flags & FLAG_TRUNCATE_SYSCALL == 0 {
        e.fd = ret as u32;
        if fd_file(e.fd, &o)
            .and_then(|f| file_path(f, &mut e.path, &o))
            .is_ok()
        {
            e.path_resolution = PATH_KERNEL;
        } else {
            file_identity(e.fd, e, &o);
        }
        if e.flags & 3 == 0 && e.flags & (0o100 | 0o1000) == 0 {
            if e.path_resolution != PATH_KERNEL || !sensitive(&e.path) {
                return Ok(());
            }
            e.kind = READ;
        }
    } else if e.kind == WRITE {
        if ret == 0 {
            return Ok(());
        }
        e.count = ret as u64;
    } else if e.kind == ACCEPT {
        let peer = e.count;
        e.count = 0;
        read_peer(peer, e);
        // Local port can still be enriched from the listening fd; preserve it
        // separately from the newly returned descriptor.
        e.flags = e.fd;
        e.fd = ret as u32;
        let _ = socket_endpoint(e.fd, e, &o);
    }
    if matches!(e.kind, WRITE | MMAP | UNLINK | RENAME | OPEN | READ)
        && e.path_resolution != PATH_UNRESOLVED
    {
        // Drop configured noise and ignored paths in the kernel so these
        // events never consume ring space or userspace processing time. A
        // rename is retained unless both sides are ignored.
        if e.kind == RENAME {
            if ignored(&e.path) && ignored(&e.path2) {
                return Ok(());
            }
        } else if ignored(&e.path) {
            return Ok(());
        }
    }
    if e.path_resolution == PATH_UNRESOLVED
        && matches!(e.kind, WRITE | MMAP | UNLINK | RENAME | OPEN | READ)
    {
        dropped(DROP_PATH);
    }
    submit(e);
    Ok(())
}
fn submit(e: &Record) {
    if let Some(mut slot) = EVENTS.reserve::<Record>(0) {
        let dst = unsafe {
            core::slice::from_raw_parts_mut(
                slot.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<Record>(),
            )
        };
        if unsafe { bpf_probe_read_kernel_buf((e as *const Record).cast::<u8>(), dst) }.is_ok() {
            slot.submit(0);
        } else {
            slot.discard(0);
            dropped(DROP_RING);
        }
    } else {
        dropped(DROP_RING);
    }
}
fn socket_endpoint(fd: u32, e: &mut Record, o: &KernelOffsets) -> Result<(), ()> {
    let file = fd_file(fd, o)?;
    let inode: u64 = read(file, o.file_inode)?;
    let mode: u16 = read(inode, o.inode_mode)?;
    if mode & 0o170000 != 0o140000 {
        return Err(());
    }
    let socket: u64 = read(file, o.file_private_data)?;
    let sk: u64 = read(socket, o.socket_sk)?;
    let _ = socket_record(sk, e, 6, o);
    let common = sk + o.sock_common as u64;
    let family: u16 = read(common, o.skc_family)?;
    if family != 2 && family != 10 {
        return Err(());
    }
    e.family = family as u32;
    e.local_port = read::<u16>(common, o.skc_num)? as u32;
    e.remote_port = u16::from_be(read::<u16>(common, o.skc_dport)?) as u32;
    if family == 2 {
        e.addr[..4].copy_from_slice(&read::<[u8; 4]>(common, o.skc_daddr)?);
    } else {
        e.addr = read(common, o.skc_v6_daddr)?;
    }
    Ok(())
}
fn read_peer(peer: u64, e: &mut Record) {
    if peer == 0 {
        return;
    }
    let family: u16 = unsafe { bpf_probe_read_user(peer as *const u16).unwrap_or(0) };
    let port: u16 = unsafe { bpf_probe_read_user((peer + 2) as *const u16).unwrap_or(0) };
    e.family = family as u32;
    e.remote_port = u16::from_be(port) as u32;
    if family == 2 {
        let a: [u8; 4] =
            unsafe { bpf_probe_read_user((peer + 4) as *const [u8; 4]).unwrap_or([0; 4]) };
        e.addr[..4].copy_from_slice(&a);
    } else if family == 10 {
        e.addr = unsafe { bpf_probe_read_user((peer + 8) as *const [u8; 16]).unwrap_or([0; 16]) };
    }
}

// These VFS permission hooks provide the resolved dentries, including symlink
// traversal, while the syscall-exit hook still determines whether it succeeded.
#[kprobe]
fn electric_eye_path_truncate(ctx: ProbeContext) -> i32 {
    let _ = truncate_path(&ctx);
    0
}
fn truncate_path(ctx: &ProbeContext) -> Result<(), ()> {
    let key = bpf_get_current_pid_tgid();
    let Some(p) = PENDING.get_ptr_mut(&key) else {
        return Ok(());
    };
    let e = unsafe { &mut *p };
    if e.kind != OPEN || e.flags & FLAG_TRUNCATE_SYSCALL == 0 {
        return Ok(());
    }
    let path: u64 = ctx.arg(0).ok_or(())?;
    let o = offsets()?;
    if kernel_path(
        read(path, o.path_mnt)?,
        read(path, o.path_dentry)?,
        &mut e.path,
        o,
    )
    .is_ok()
    {
        e.path_resolution = PATH_KERNEL;
    }
    Ok(())
}
#[kprobe]
fn electric_eye_path_unlink(ctx: ProbeContext) -> i32 {
    let _ = mutation_path(&ctx, false);
    0
}
#[kprobe]
fn electric_eye_path_rename(ctx: ProbeContext) -> i32 {
    let _ = mutation_path(&ctx, true);
    0
}
fn mutation_path(ctx: &ProbeContext, rename: bool) -> Result<(), ()> {
    let key = bpf_get_current_pid_tgid();
    let Some(p) = PENDING.get_ptr_mut(&key) else {
        return Ok(());
    };
    let e = unsafe { &mut *p };
    let o = offsets()?;
    if (rename && e.kind != RENAME) || (!rename && e.kind != UNLINK) {
        return Ok(());
    }
    let dir: u64 = ctx.arg(0).ok_or(())?;
    let dentry: u64 = ctx.arg(1).ok_or(())?;
    if kernel_path(read(dir, o.path_mnt)?, dentry, &mut e.path, &o).is_ok() {
        e.path_resolution = PATH_KERNEL;
    }
    if rename {
        let dir: u64 = ctx.arg(2).ok_or(())?;
        let dentry: u64 = ctx.arg(3).ok_or(())?;
        if kernel_path(read(dir, o.path_mnt)?, dentry, &mut e.path2, &o).is_ok() {
            e.path2_resolution = PATH_KERNEL;
        }
    }
    Ok(())
}
#[tracepoint(category = "sched", name = "sched_process_exec")]
fn electric_eye_exec(_ctx: TracePointContext) -> i32 {
    lifecycle(EXEC);
    0
}
#[tracepoint(category = "sched", name = "sched_process_exit")]
fn electric_eye_exit(_ctx: TracePointContext) -> i32 {
    let key = bpf_get_current_pid_tgid();
    let _ = PENDING.remove(&key);
    let _ = NET_PENDING.remove(&NetKey {
        tid: key,
        kind: SENT,
        pad: 0,
    });
    let _ = NET_PENDING.remove(&NetKey {
        tid: key,
        kind: RECEIVED,
        pad: 0,
    });
    if let Ok(o) = offsets() {
        if read::<u64>(task(), o.task_signal)
            .and_then(|signal| read::<i32>(signal, o.signal_live))
            .is_ok_and(|live| live == 0)
        {
            lifecycle(EXIT);
        }
    }
    0
}
fn lifecycle(kind: u32) {
    let Ok(o) = offsets() else {
        return;
    };
    if !capture_current(o) {
        return;
    }
    let Some(mut slot) = EVENTS.reserve::<Record>(0) else {
        dropped(DROP_RING);
        return;
    };
    let e = unsafe { &mut *slot.as_mut_ptr() };
    if !fill_identity(e, &o) {
        slot.discard(0);
        return;
    }
    e.kind = kind;
    metadata(e, task(), &o);
    if kind == EXIT {
        e.exit_code = read(task(), o.task_exit_code).unwrap_or(0);
    }
    slot.submit(0);
}
#[tracepoint(category = "sock", name = "inet_sock_set_state")]
fn electric_eye_sock_state(ctx: TracePointContext) -> i32 {
    let _ = socket_state(&ctx);
    0
}
fn socket_state(ctx: &TracePointContext) -> Result<(), ()> {
    let o = offsets()?;
    let s = unsafe { SOCK_OFFSETS.get(&0).copied().ok_or(())? };
    let state: i32 = unsafe { ctx.read_at(s.newstate as usize).map_err(|_| ())? };
    if !matches!(state, 1 | 2 | 7 | 10) {
        return Ok(());
    }
    let sk: u64 = unsafe { ctx.read_at(s.skaddr as usize).map_err(|_| ())? };
    if matches!(state, 1 | 7) {
        if unsafe { SOCKETS.get(&sk) }.is_none() {
            return Ok(());
        }
    } else if !capture_current(o) {
        return Ok(());
    }
    let Some(mut slot) = EVENTS.reserve::<Record>(0) else {
        dropped(DROP_RING);
        return Ok(());
    };
    let e = unsafe { &mut *slot.as_mut_ptr() };
    if matches!(state, 1 | 7) {
        if saved_socket(sk, e, o).is_err() {
            slot.discard(0);
            return Ok(());
        }
    } else if !fill_identity(e, o) || socket_record(sk, e, 6, o).is_err() {
        slot.discard(0);
        return Ok(());
    }
    e.state = state as u32;
    e.kind = match state {
        2 => CONNECT,
        10 => LISTEN,
        _ => NET_STATE,
    };
    slot.submit(0);
    Ok(())
}
// Byte deltas are immutable events. There is no PID-indexed counter map to
// fill, reset, race with readers, or confuse with a reused process identifier.
#[kretprobe]
fn electric_eye_tcp_sent(ctx: RetProbeContext) -> i32 {
    traffic(&ctx, SENT);
    0
}
#[kretprobe]
fn electric_eye_tcp_recv(ctx: RetProbeContext) -> i32 {
    traffic(&ctx, RECEIVED);
    0
}
#[kretprobe]
fn electric_eye_udp_sent(ctx: RetProbeContext) -> i32 {
    traffic(&ctx, SENT);
    0
}
#[kretprobe]
fn electric_eye_udp_recv(ctx: RetProbeContext) -> i32 {
    traffic(&ctx, RECEIVED);
    0
}
fn traffic(ctx: &RetProbeContext, kind: u32) {
    let key = NetKey {
        tid: bpf_get_current_pid_tgid(),
        kind,
        pad: 0,
    };
    if let Some(ptr) = NET_PENDING.get_ptr_mut(&key) {
        let e = unsafe { &mut *ptr };
        let ret: i32 = ctx.ret();
        if ret > 0 {
            if let Ok(o) = offsets() {
                let addr = e.addr;
                let port = e.remote_port;
                let _ = socket_record(e.result as u64, e, e.protocol, o);
                if e.protocol == 17 {
                    if port != 0 {
                        e.addr = addr;
                        e.remote_port = port;
                    }
                    kernel_peer(e.count, e, o);
                }
            }
            e.result = 0;
            e.count = ret as u64;
            e.ts_ns = unsafe { bpf_ktime_get_boot_ns() };
            submit(e);
        }
        let _ = NET_PENDING.remove(&key);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
