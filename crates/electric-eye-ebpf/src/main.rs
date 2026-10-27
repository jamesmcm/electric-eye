#![no_std]
#![no_main]

#[path = "../../electric-eye-core/src/wire.rs"]
mod wire;
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid,
        bpf_get_ns_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_loop, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
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
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_COUNT, 0);
#[map]
static DIR_SCRATCH: PerCpuArray<[u8; PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);
#[map]
static BUILD_SCRATCH: PerCpuArray<[u8; 1024]> = PerCpuArray::with_max_entries(1, 0);
#[map]
static PATH_SCRATCH: PerCpuArray<[u8; 1024]> = PerCpuArray::with_max_entries(1, 0);

fn dropped(reason: u32) {
    if let Some(p) = DROPPED.get_ptr_mut(reason) {
        unsafe {
            *p += 1;
        }
    }
}
fn offsets() -> Result<KernelOffsets, ()> {
    unsafe { KERNEL_OFFSETS.get(&0).copied().ok_or(()) }
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
    let ids = bpf_get_current_pid_tgid();
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
    let parent: u64 = read(leader, o.task_real_parent)?;
    e.ppid = if ns.tgid == (ids >> 32) as u32 {
        read(parent, o.task_tgid)?
    } else {
        0
    };
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
        }
    }
    Ok(true)
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

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
fn electric_eye_sys_enter(ctx: TracePointContext) -> i32 {
    let _ = enter(&ctx);
    0
}
fn enter(ctx: &TracePointContext) -> Result<(), ()> {
    let o = offsets()?;
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
        OP_OPEN | OP_OPENAT | OP_OPENAT2 => {
            e.kind = OPEN;
            let (ptr, dirfd, flags) = if op == OP_OPEN {
                (args[0], -100, args[1])
            } else if op == OP_OPENAT {
                (args[1], args[0] as i32, args[2])
            } else {
                (args[1], args[0] as i32, unsafe {
                    bpf_probe_read_user(args[2] as *const u64).unwrap_or(0)
                })
            };
            e.flags = flags as u32;
            e.path_resolution = syscall_path(ptr, dirfd, &mut e.path, &o);
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
    if e.kind == OPEN {
        e.fd = ret as u32;
        if fd_file(e.fd, &o)
            .and_then(|f| file_path(f, &mut e.path, &o))
            .is_ok()
        {
            e.path_resolution = PATH_KERNEL;
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
    if key as u32 == (key >> 32) as u32 {
        lifecycle(EXIT);
    }
    0
}
fn lifecycle(kind: u32) {
    let Ok(o) = offsets() else {
        return;
    };
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
    if state != 2 && state != 10 {
        return Ok(());
    }
    let family: u16 = unsafe { ctx.read_at(s.family as usize).map_err(|_| ())? };
    let protocol: u16 = unsafe { ctx.read_at(s.protocol as usize).map_err(|_| ())? };
    if (family != 2 && family != 10) || protocol != 6 {
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
    e.kind = if state == 2 { CONNECT } else { LISTEN };
    e.family = family as u32;
    e.local_port = unsafe { ctx.read_at::<u16>(s.sport as usize).unwrap_or(0) } as u32;
    e.remote_port = unsafe { ctx.read_at::<u16>(s.dport as usize).unwrap_or(0) } as u32;
    let at = if family == 2 {
        if state == 2 {
            s.daddr4
        } else {
            s.saddr4
        }
    } else if state == 2 {
        s.daddr6
    } else {
        s.saddr6
    };
    if family == 2 {
        let a: [u8; 4] = unsafe { ctx.read_at(at as usize).unwrap_or([0; 4]) };
        e.addr[..4].copy_from_slice(&a);
    } else {
        e.addr = unsafe { ctx.read_at(at as usize).unwrap_or([0; 16]) };
    }
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
    let ret: i32 = ctx.ret();
    if ret <= 0 {
        return;
    }
    let Ok(o) = offsets() else {
        return;
    };
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
    e.count = ret as u64;
    slot.submit(0);
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
