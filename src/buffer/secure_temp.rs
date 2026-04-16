//! Secure temporary file handling with automatic cleanup and secure deletion.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tempfile::Builder;

/// Known copy-on-write filesystem magic numbers (Linux).
#[cfg(target_os = "linux")]
mod cow_filesystems {
    pub const BTRFS_MAGIC: i64 = 0x9123683E;
    pub const ZFS_MAGIC: i64 = 0x2FC12FC1;
    pub const BCACHEFS_MAGIC: i64 = 0xCA451A4E_u32 as i64;
    pub const NILFS_MAGIC: i64 = 0x3434;
}

/// Check if the system temp directory is on a copy-on-write filesystem.
///
/// Returns Some(filesystem_name) if a CoW filesystem is detected, None otherwise.
/// On non-Linux systems, always returns None.
#[cfg(target_os = "linux")]
pub fn detect_cow_filesystem() -> Option<&'static str> {
    use cow_filesystems::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let temp_dir = std::env::temp_dir();
    let path = CString::new(temp_dir.to_string_lossy().as_bytes()).ok()?;

    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    let result = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };

    if result != 0 {
        return None;
    }

    let stat = unsafe { stat.assume_init() };
    match stat.f_type {
        BTRFS_MAGIC => Some("btrfs"),
        ZFS_MAGIC => Some("ZFS"),
        BCACHEFS_MAGIC => Some("bcachefs"),
        NILFS_MAGIC => Some("NILFS2"),
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_cow_filesystem() -> Option<&'static str> {
    None
}

/// A temporary file that securely overwrites its contents before deletion.
pub struct SecureTempFile {
    /// Path to the temp file. None if already deleted.
    path: Option<PathBuf>,
    file: File,
}

impl SecureTempFile {
    /// Create a new secure temporary file.
    ///
    /// The file is created with:
    /// - Random filename (no identifiable prefix for security)
    /// - Mode 0600 on Unix (owner read/write only)
    /// - Located in the system temp directory
    pub fn new() -> io::Result<Self> {
        // Use Builder with minimal/random prefix to avoid identifiable filenames.
        // tempfile crate creates files with mode 0600 on Unix by default.
        let temp = Builder::new()
            .prefix(".") // Hidden file, minimal prefix
            .tempfile()?;
        let (file, path) = temp.keep().map_err(|e| e.error)?;
        Ok(Self {
            path: Some(path),
            file,
        })
    }

    /// Write data to the file, overwriting any existing content.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.write_all(data)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Read all data from the file.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut data = Vec::new();
        self.file.read_to_end(&mut data)?;
        Ok(data)
    }

    /// Get the current size of the file.
    pub fn len(&self) -> io::Result<u64> {
        self.file.metadata().map(|m| m.len())
    }

    /// Returns true if the file is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|l| l == 0)
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn set_len(&self, size: u64) -> io::Result<()> {
        self.file.set_len(size)
    }

    /// Append data to the end of the file. Used for streaming writes.
    pub fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(data)?;
        Ok(())
    }

    /// Securely wipe file contents (overwrite + truncate) without deleting.
    /// Used to clear stale data from the inactive ping-pong file.
    pub fn wipe(&mut self) -> io::Result<()> {
        self.secure_overwrite()?;
        self.file.set_len(0)?;
        self.file.sync_all()
    }

    /// Securely delete the file by overwriting with zeros, then 0xFF, then removing.
    /// Note: This consumes self. The Drop impl handles cleanup if this isn't called.
    pub fn secure_delete(mut self) -> io::Result<()> {
        self.secure_overwrite()?;
        self.file.sync_all()?;
        // Take path to prevent Drop from trying to delete again
        let path = self.path.take();
        // self will be dropped here, closing the file handle
        // Then we delete the file
        drop(self);
        if let Some(p) = path {
            std::fs::remove_file(&p)?;
        }
        Ok(())
    }

    /// Overwrite file contents with patterns for secure deletion.
    fn secure_overwrite(&mut self) -> io::Result<()> {
        let len = self.file.metadata()?.len() as usize;
        if len == 0 {
            return Ok(());
        }

        // First pass: zeros
        self.file.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; len.min(65536)];
        let mut remaining = len;
        while remaining > 0 {
            let to_write = remaining.min(zeros.len());
            self.file.write_all(&zeros[..to_write])?;
            remaining -= to_write;
        }
        self.file.sync_all()?;

        // Second pass: 0xFF
        self.file.seek(SeekFrom::Start(0))?;
        let ones = vec![0xFFu8; len.min(65536)];
        remaining = len;
        while remaining > 0 {
            let to_write = remaining.min(ones.len());
            self.file.write_all(&ones[..to_write])?;
            remaining -= to_write;
        }
        self.file.sync_all()?;

        Ok(())
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        // Best-effort secure cleanup on drop (e.g., during panic)
        if self.path.is_some() {
            let _ = self.secure_overwrite();
            // Ensure overwrites hit disk before unlinking
            let _ = self.file.sync_all();
            if let Some(path) = self.path.take() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_roundtrip() {
        let mut temp = SecureTempFile::new().unwrap();
        let data = b"test data for secure temp file";
        temp.write_all(data).unwrap();
        let read_back = temp.read_all().unwrap();
        assert_eq!(data.as_slice(), read_back.as_slice());
    }

    #[test]
    fn test_overwrite() {
        let mut temp = SecureTempFile::new().unwrap();
        temp.write_all(b"first data").unwrap();
        temp.write_all(b"second").unwrap();
        let read_back = temp.read_all().unwrap();
        assert_eq!(b"second".as_slice(), read_back.as_slice());
    }

    #[test]
    fn test_secure_delete() {
        let temp = SecureTempFile::new().unwrap();
        let path = temp.path.clone().unwrap();
        assert!(path.exists());
        temp.secure_delete().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_len() {
        let mut temp = SecureTempFile::new().unwrap();
        assert_eq!(temp.len().unwrap(), 0);
        temp.write_all(b"12345").unwrap();
        assert_eq!(temp.len().unwrap(), 5);
    }

    #[test]
    fn test_drop_cleans_up() {
        let path;
        {
            let temp = SecureTempFile::new().unwrap();
            path = temp.path.clone().unwrap();
            assert!(path.exists());
            // temp drops here
        }
        assert!(!path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = SecureTempFile::new().unwrap();
        let path = temp.path.as_ref().unwrap();
        let metadata = std::fs::metadata(path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;

        // Verify file is created with restricted permissions (0600)
        assert_eq!(
            mode, 0o600,
            "Temp file should have mode 0600, got {:o}",
            mode
        );

        // Verify filename starts with dot (hidden)
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert!(
            filename.starts_with('.'),
            "Temp file should be hidden (start with .)"
        );
    }

    #[test]
    fn test_detect_cow_filesystem_runs() {
        // Just verify the function runs without panicking.
        // Result depends on the actual filesystem, so we don't assert a specific value.
        let result = super::detect_cow_filesystem();
        // If detected, it should be a known filesystem name
        if let Some(name) = result {
            assert!(
                ["btrfs", "ZFS", "bcachefs", "NILFS2"].contains(&name),
                "Unknown CoW filesystem: {}",
                name
            );
        }
    }
}
