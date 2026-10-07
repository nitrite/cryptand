//! Positional file I/O on every platform: `FileExt` on Unix, `seek_read` and
//! `seek_write` on Windows. The Windows calls also move the file cursor;
//! nothing that uses this trait relies on the cursor.
//!
//! The method names match `std::os::unix::fs::FileExt`, so a call site only
//! changes its import (F-063).

use std::fs::File;
use std::io::{Error, ErrorKind, Result};

pub trait PosIo {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize>;
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize>;

    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset) {
                Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match self.write_at(buf, offset) {
                Ok(0) => return Err(Error::new(ErrorKind::WriteZero, "failed to write whole buffer")),
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl PosIo for File {
    #[cfg(unix)]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, offset)
    }
    #[cfg(unix)]
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        std::os::unix::fs::FileExt::write_at(self, buf, offset)
    }
    #[cfg(windows)]
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        std::os::windows::fs::FileExt::seek_read(self, buf, offset)
    }
    #[cfg(windows)]
    fn write_at(&self, buf: &[u8], offset: u64) -> Result<usize> {
        std::os::windows::fs::FileExt::seek_write(self, buf, offset)
    }
}
