//! Bounded reads of metadata which may be controlled by another user.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn open_regular(path: &Path, max_bytes: u64) -> io::Result<File> {
    // Opening a FIFO must not wait for a writer. Check the opened descriptor,
    // rather than a pathname which could be substituted between stat and open.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata must be a bounded regular file",
        ));
    }
    Ok(file)
}

pub fn read_text(path: &Path, max_bytes: usize) -> io::Result<String> {
    let file = open_regular(path, max_bytes as u64)?;
    let mut text = String::new();
    file.take(max_bytes as u64 + 1).read_to_string(&mut text)?;
    if text.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata grew beyond its byte limit",
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_fifos_symlinks_and_oversized_files() {
        use std::ffi::CString;
        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("fifo");
        let name = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_text(&fifo, 1024).is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_text(&link, 1024).is_err());
        let file = temp.path().join("file");
        std::fs::write(&file, b"12345").unwrap();
        assert!(read_text(&file, 4).is_err());
        assert_eq!(read_text(&file, 5).unwrap(), "12345");
    }
}
