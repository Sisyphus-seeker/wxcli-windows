use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

pub(crate) fn open_read_shared(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(windows)]
    options.share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004);

    options.open(path)
}

/// Read an exact prefix while allowing the live Weixin process to keep the file open.
pub fn read_prefix_shared(path: &Path, length: usize) -> io::Result<Vec<u8>> {
    let mut file = open_read_shared(path)?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_requested_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.db");
        std::fs::write(&path, b"abcdefgh").unwrap();

        assert_eq!(read_prefix_shared(&path, 4).unwrap(), b"abcd");
    }
}
