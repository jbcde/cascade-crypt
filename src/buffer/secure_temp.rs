//! Secure temporary file handling with automatic cleanup and secure deletion.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tempfile::Builder;

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
        Ok(Self { path: Some(path), file })
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
        assert_eq!(mode, 0o600, "Temp file should have mode 0600, got {:o}", mode);

        // Verify filename starts with dot (hidden)
        let filename = path.file_name().unwrap().to_str().unwrap();
        assert!(filename.starts_with('.'), "Temp file should be hidden (start with .)");
    }
}
