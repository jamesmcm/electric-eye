#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

#[repr(C)]
pub struct RawExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub reserved: u32,
    pub comm: [u8; 16],
}

#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[tracepoint(category = "sched", name = "sched_process_exec")]
fn electric_eye_exec(_ctx: TracePointContext) -> i32 {
    match try_emit() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_emit() -> Result<(), i64> {
    let Ok(comm) = bpf_get_current_comm() else {
        return Ok(());
    };

    let Some(mut slot) = EXEC_EVENTS.reserve::<RawExecEvent>(0) else {
        return Ok(());
    };

    slot.write(RawExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        ppid: 0,
        uid: bpf_get_current_uid_gid() as u32,
        reserved: 0,
        comm,
    });
    slot.submit(0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
