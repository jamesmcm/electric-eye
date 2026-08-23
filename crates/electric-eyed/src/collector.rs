use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;

pub const EVENT_MAP: &str = "EXEC_EVENTS";
pub const PROGRAM_NAME: &str = "electric_eye_exec";

const RAW_EVENT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

impl RawExecEvent {
    pub fn comm_str(&self) -> String {
        let end = self
            .comm
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

pub fn decode(data: &[u8]) -> Option<RawExecEvent> {
    if data.len() < RAW_EVENT_LEN {
        return None;
    }
    Some(RawExecEvent {
        pid: u32::from_le_bytes(data[0..4].try_into().ok()?),
        ppid: u32::from_le_bytes(data[4..8].try_into().ok()?),
        uid: u32::from_le_bytes(data[8..12].try_into().ok()?),
        comm: data[16..32].try_into().ok()?,
    })
}

pub struct Collector {
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
}

impl Collector {
    pub fn load(object_path: &Path) -> Result<Self> {
        let mut bpf = Ebpf::load_file(object_path)
            .with_context(|| format!("failed to load eBPF object {}", object_path.display()))?;

        let program: &mut TracePoint = bpf
            .program_mut(PROGRAM_NAME)
            .with_context(|| format!("program {PROGRAM_NAME} missing from the object"))?
            .try_into()?;
        program.load()?;
        program
            .attach("sched", "sched_process_exec")
            .context("failed to attach sched_process_exec tracepoint")?;

        let ring = RingBuf::try_from(
            bpf.take_map(EVENT_MAP)
                .with_context(|| format!("map {EVENT_MAP} missing from the object"))?,
        )?;

        Ok(Self { _bpf: bpf, ring })
    }

    pub fn poll_forever<F: FnMut(RawExecEvent)>(&mut self, mut handler: F) -> ! {
        loop {
            let drained = self.drain(&mut handler).unwrap_or_else(|err| {
                log::warn!("event drain failed: {err:#}");
                0
            });
            if drained == 0 {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn drain<F: FnMut(RawExecEvent)>(&mut self, handler: &mut F) -> Result<usize> {
        let mut count = 0;
        while let Some(item) = self.ring.next() {
            match decode(&item) {
                Some(event) => {
                    handler(event);
                    count += 1;
                }
                None => bail!("malformed event of {} bytes", item.len()),
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_round_trip_bytes() {
        let mut raw = RawExecEvent {
            pid: 1234,
            ppid: 7,
            uid: 1000,
            comm: [0; 16],
        };
        raw.comm[..4].copy_from_slice(b"bash");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&raw.pid.to_le_bytes());
        bytes.extend_from_slice(&raw.ppid.to_le_bytes());
        bytes.extend_from_slice(&raw.uid.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&raw.comm);

        let decoded = decode(&bytes).expect("valid layout must decode");
        assert_eq!(decoded.pid, 1234);
        assert_eq!(decoded.ppid, 7);
        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.comm_str(), "bash");
    }

    #[test]
    fn rejects_short_buffers() {
        assert!(decode(&[0u8; 8]).is_none());
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn comm_truncates_at_nul() {
        let mut raw = RawExecEvent {
            pid: 1,
            ppid: 1,
            uid: 0,
            comm: [0; 16],
        };
        raw.comm.copy_from_slice(b"rust-analyzer\0\0\0");
        assert_eq!(raw.comm_str(), "rust-analyzer");
    }
}
