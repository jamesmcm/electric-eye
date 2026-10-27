#![allow(dead_code)]
//! Versioned kernel/userspace ABI. This file is also compiled directly by the
//! no_std BPF crate; keep it independent of serde and operating-system crates.
pub const ABI_VERSION: u32 = 4;
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
pub const FORK: u32 = 13;
pub const SOCKET: u32 = 14;
pub const BIND: u32 = 15;
pub const NET_RESULT: u32 = 16;
pub const NET_STATE: u32 = 17;
pub const NET_CLOSE: u32 = 18;
pub const OP_SOCKET: u32 = 13;
pub const OP_BIND: u32 = 14;
pub const OP_CONNECT: u32 = 15;
pub const OP_SOERROR: u32 = 16;
pub const OP_TRUNCATE: u32 = 17;
pub const OP_FTRUNCATE: u32 = 18;
pub const OP_CREAT: u32 = 19;
pub const FLAG_TRUNCATE_SYSCALL: u32 = 1 << 31;
pub const FLAG_SO_ERROR: u32 = 1;
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
    pub socket_id: u64,
    pub netns: u64,
    pub protocol: u32,
    pub state: u32,
    pub local_addr: [u8; 16],
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
    pub exe_inode: u64,
    pub exe_dev: u32,
    pub parent_start_ns: u64,
    pub euid: u32,
    pub exec_id: u32,
    pub exit_code: i32,
    pub metadata_flags: u32,
    pub fd: u32,
    pub dirfd: i32,
    pub file_dev: u32,
    pub family: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub path_resolution: u32,
    pub path2_resolution: u32,
    pub path_ptr: u64,
    pub file_inode: u64,
    pub addr: [u8; 16],
    pub comm: [u8; 16],
    pub parent_comm: [u8; 16],
    pub cgroup: [u8; 256],
    pub exe: [u8; PATH_LEN],
    pub path: [u8; PATH_LEN],
    pub path2: [u8; PATH_LEN],
}
impl Record {
    pub const ZERO: Self = Self {
        socket_id: 0,
        netns: 0,
        protocol: 0,
        state: 0,
        local_addr: [0; 16],
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
        exe_inode: 0,
        exe_dev: 0,
        parent_start_ns: 0,
        euid: 0,
        exec_id: 0,
        exit_code: 0,
        metadata_flags: 0,
        fd: 0,
        dirfd: 0,
        file_dev: 0,
        family: 0,
        local_port: 0,
        remote_port: 0,
        path_resolution: 0,
        path2_resolution: 0,
        path_ptr: 0,
        file_inode: 0,
        addr: [0; 16],
        comm: [0; 16],
        parent_comm: [0; 16],
        cgroup: [0; 256],
        exe: [0; PATH_LEN],
        path: [0; PATH_LEN],
        path2: [0; PATH_LEN],
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelOffsets {
    pub skb_head: u32,
    pub skb_network: u32,
    pub skb_transport: u32,
    pub socket_type: u32,
    pub skc_net: u32,
    pub net_inum: u32,
    pub skc_rcv_saddr: u32,
    pub skc_v6_rcv_saddr: u32,
    pub msg_name: u32,
    pub inode_ino: u32,
    pub inode_sb: u32,
    pub sb_dev: u32,
    pub task_pid: u32,
    pub task_thread_pid: u32,
    pub pid_level: u32,
    pub pid_numbers: u32,
    pub upid_ns: u32,
    pub upid_nr: u32,
    pub pid_ns_inum: u32,
    pub task_cred: u32,
    pub cred_uid: u32,
    pub cred_euid: u32,
    pub task_exec_id: u32,
    pub task_exit_code: u32,
    pub task_signal: u32,
    pub signal_live: u32,
    pub mm_arg_start: u32,
    pub mm_arg_end: u32,
    pub task_cgroups: u32,
    pub css_dfl_cgrp: u32,
    pub cgroup_kn: u32,
    pub kn_parent: u32,
    pub kn_name: u32,
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
    pub skc_state: u32,
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
    pub skaddr: u32,
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
