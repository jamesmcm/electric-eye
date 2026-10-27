//! Minimal read-only BTF member lookup. Aya keeps member inspection private;
//! parsing the documented BTF records avoids hard-coded kernel struct layouts.
use anyhow::{Context, Result, bail};
use std::collections::HashMap;

type Members = Vec<(String, u32, u32)>;
type BtfTypes = Vec<(String, Members)>;

#[derive(Default)]
pub struct Layout {
    members: HashMap<(String, String), u32>,
}
impl Layout {
    pub fn load() -> Result<Self> {
        Self::parse(
            &std::fs::read("/sys/kernel/btf/vmlinux")
                .context("kernel BTF is required for event-time attribution")?,
        )
    }
    pub fn member(&self, ty: &str, field: &str) -> Result<u32> {
        self.members
            .get(&(ty.into(), field.into()))
            .copied()
            .with_context(|| format!("kernel BTF has no byte-aligned {ty}.{field}"))
    }
    fn parse(data: &[u8]) -> Result<Self> {
        let u32at = |at: usize| -> Result<u32> {
            Ok(u32::from_le_bytes(
                data.get(at..at + 4).context("truncated BTF")?.try_into()?,
            ))
        };
        if data.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            bail!("unsupported BTF format/endianness");
        }
        let header = u32at(4)? as usize;
        let start = header
            .checked_add(u32at(8)? as usize)
            .context("BTF overflow")?;
        let end = start
            .checked_add(u32at(12)? as usize)
            .context("BTF overflow")?;
        let strings_start = header
            .checked_add(u32at(16)? as usize)
            .context("BTF overflow")?;
        let strings_end = strings_start
            .checked_add(u32at(20)? as usize)
            .context("BTF overflow")?;
        let strings = data
            .get(strings_start..strings_end)
            .context("invalid BTF strings")?;
        let string = |offset: u32| -> Result<String> {
            let bytes = strings
                .get(offset as usize..)
                .context("invalid BTF string offset")?;
            let n = bytes
                .iter()
                .position(|b| *b == 0)
                .context("unterminated BTF string")?;
            Ok(std::str::from_utf8(&bytes[..n])?.into())
        };
        if end > data.len() {
            bail!("truncated BTF types");
        }
        let mut result = Self::default();
        let mut at = start;
        let mut types = vec![(String::new(), Vec::<(String, u32, u32)>::new())];
        while at < end {
            let name = u32at(at)?;
            let info = u32at(at + 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 65535) as usize;
            let extra = match kind {
                1 => 4,
                2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
                3 => 12,
                4 | 5 => count * 12,
                6 => count * 8,
                13 => count * 8,
                14 => 4,
                15 => count * 12,
                17 => 4,
                19 => count * 12,
                _ => bail!("unsupported BTF kind {kind}"),
            };
            if at + 12 + extra > end {
                bail!("truncated BTF member list");
            }
            let mut members = Vec::new();
            if kind == 4 || kind == 5 {
                for i in 0..count {
                    let member = at + 12 + i * 12;
                    let field = string(u32at(member)?)?;
                    let encoded = u32at(member + 8)?;
                    let bit_offset = if info >> 31 != 0 {
                        encoded & 0x00ff_ffff
                    } else {
                        encoded
                    };
                    let bitfield = info >> 31 != 0 && encoded >> 24 != 0;
                    if !bitfield && bit_offset % 8 == 0 {
                        members.push((field, u32at(member + 4)?, bit_offset / 8));
                    }
                }
            }
            types.push((string(name)?, members));
            at += 12 + extra;
        }
        fn flatten(
            types: &BtfTypes,
            id: usize,
            base: u32,
            depth: usize,
            out: &mut Vec<(String, u32)>,
        ) {
            if depth > 16 {
                return;
            }
            let Some((_, members)) = types.get(id) else {
                return;
            };
            for (name, ty, offset) in members {
                if name.is_empty() {
                    flatten(types, *ty as usize, base + offset, depth + 1, out);
                } else {
                    out.push((name.clone(), base + offset));
                }
            }
        }
        for (id, (name, _)) in types.iter().enumerate() {
            if name.is_empty() {
                continue;
            }
            let mut members = Vec::new();
            flatten(&types, id, 0, 0, &mut members);
            for (field, offset) in members {
                result.members.insert((name.clone(), field), offset);
            }
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_live_kernel_members_without_privileges() {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let btf = Layout::load().unwrap();
        assert!(btf.member("task_struct", "start_boottime").is_ok());
        assert!(btf.member("file", "f_path").is_ok());
        assert!(btf.member("mount", "mnt").is_ok());
        assert!(btf.member("qstr", "len").is_ok());
        assert!(btf.member("file", "f_inode").is_ok());
    }
    #[test]
    fn rejects_truncation() {
        assert!(Layout::parse(&[0x9f, 0xeb, 1, 0]).is_err());
    }
}
