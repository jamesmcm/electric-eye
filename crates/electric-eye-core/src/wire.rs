#![allow(dead_code)]
//! Versioned kernel/userspace ABI. This file is also compiled directly by the
//! no_std BPF crate; keep it independent of serde and operating-system crates.
pub const ABI_VERSION: u32 = 2;
pub const PATH_LEN: usize = 512;
pub const EXEC: u32 = 0;
pub const EXIT: u32 = 1;
pub const CONNECT: u32 = 2;
pub const LISTEN: u32 = 3;
pub const ACCEPT: u32 = 4;
pub const OPEN: u32 = 5;
pub const READ: u32 = 6;
pub const WRITE: u32 = 7;
pub const MMAP: u32 = 8;
pub const UNLINK: u32 = 9;
pub const RENAME: u32 = 10;
pub const SENT: u32 = 11;
pub const RECEIVED: u32 = 12;
pub const PATH_KERNEL: u32 = 1;
pub const PATH_LEXICAL: u32 = 2;
pub const PATH_UNRESOLVED: u32 = 0;
pub const OP_OPEN: u32 = 1;
pub const OP_OPENAT: u32 = 2;
pub const OP_OPENAT2: u32 = 3;
pub const OP_WRITE: u32 = 4;
pub const OP_SENDFILE: u32 = 5;
pub const OP_COPY: u32 = 6;
pub const OP_MMAP: u32 = 7;
pub const OP_UNLINK: u32 = 8;
pub const OP_UNLINKAT: u32 = 9;
pub const OP_RENAME: u32 = 10;
pub const OP_RENAMEAT: u32 = 11;
pub const OP_ACCEPT: u32 = 12;
pub const DROP_RING: u32 = 0;
pub const DROP_PENDING: u32 = 1;
pub const DROP_IDENTITY: u32 = 2;
pub const DROP_PATH: u32 = 3;
pub const DROP_COUNT: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Record {
    pub version: u32,
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub flags: u32,
    pub start_ns: u64,
    pub ts_ns: u64,
    pub count: u64,
    pub result: i64,
    pub fd: u32,
    pub family: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub path_resolution: u32,
    pub path2_resolution: u32,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
    pub parent_comm: [u8; 16],
    pub exe: [u8; PATH_LEN],
    pub path: [u8; PATH_LEN],
    pub path2: [u8; PATH_LEN],
}
impl Record {
    pub const ZERO: Self = Self {
        version: ABI_VERSION,
        kind: 0,
        pid: 0,
        uid: 0,
        ppid: 0,
        flags: 0,
        start_ns: 0,
        ts_ns: 0,
        count: 0,
        result: 0,
        fd: 0,
        family: 0,
        local_port: 0,
        remote_port: 0,
        path_resolution: 0,
        path2_resolution: 0,
        addr: [0; 16],
        comm: [0; 16],
        parent_comm: [0; 16],
        exe: [0; PATH_LEN],
        path: [0; PATH_LEN],
        path2: [0; PATH_LEN],
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelOffsets {
    pub task_comm: u32,
    pub task_group_leader: u32,
    pub task_start_boottime: u32,
    pub task_real_parent: u32,
    pub task_tgid: u32,
    pub task_fs: u32,
    pub task_files: u32,
    pub task_mm: u32,
    pub mm_exe_file: u32,
    pub fs_root: u32,
    pub fs_pwd: u32,
    pub files_fdt: u32,
    pub fdt_fd: u32,
    pub fdt_max_fds: u32,
    pub file_path: u32,
    pub file_inode: u32,
    pub inode_mode: u32,
    pub path_mnt: u32,
    pub path_dentry: u32,
    pub dentry_parent: u32,
    pub dentry_name: u32,
    pub qstr_len: u32,
    pub qstr_name: u32,
    pub vfsmount_root: u32,
    pub mount_mnt: u32,
    pub mount_parent: u32,
    pub mount_mountpoint: u32,
    pub enter_id: u32,
    pub enter_args: u32,
    pub exit_ret: u32,
    pub own_pid: u32,
    pub file_private_data: u32,
    pub socket_sk: u32,
    pub sock_common: u32,
    pub skc_family: u32,
    pub skc_num: u32,
    pub skc_dport: u32,
    pub skc_daddr: u32,
    pub skc_v6_daddr: u32,
    pub own_ns_dev: u64,
    pub own_ns_ino: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockOffsets {
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
