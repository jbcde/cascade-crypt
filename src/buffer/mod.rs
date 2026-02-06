//! Adaptive buffering for encryption layers with automatic RAM-to-disk switching.

mod secure_temp;

use std::io;
use zeroize::Zeroizing;

pub use secure_temp::{detect_cow_filesystem, SecureTempFile};

/// Error type for LayerBuffer::process operations.
///
/// This wraps both IO errors from disk operations and crypto errors from the
/// processing function, allowing the caller to handle them appropriately.
#[derive(Debug)]
pub enum ProcessError<E> {
    /// IO error from disk operations.
    Io(io::Error),
    /// Crypto error from the processing function.
    Crypto(E),
}

/// Buffer mode for encryption/decryption operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BufferMode {
    /// Force RAM-only buffering (may fail on large files).
    Ram,
    /// Force disk buffering from the start.
    ///
    /// Note: Each layer operation still reads the full data into memory for
    /// processing (cipher APIs require contiguous input). Disk mode bounds peak
    /// memory to ~2x the data size (input + output of one layer) rather than
    /// accumulating all layers in RAM. It does not provide constant-memory
    /// streaming.
    Disk,
    /// Automatically switch from RAM to disk when memory pressure is detected.
    #[default]
    Auto,
}

impl std::str::FromStr for BufferMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ram" => Ok(BufferMode::Ram),
            "disk" => Ok(BufferMode::Disk),
            "auto" => Ok(BufferMode::Auto),
            _ => Err(format!(
                "Invalid buffer mode: '{}'. Use 'ram', 'disk', or 'auto'",
                s
            )),
        }
    }
}

impl std::fmt::Display for BufferMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferMode::Ram => write!(f, "ram"),
            BufferMode::Disk => write!(f, "disk"),
            BufferMode::Auto => write!(f, "auto"),
        }
    }
}

/// Check if we should switch from RAM to disk buffering.
///
/// Returns true if memory pressure is detected and we should spill to disk.
pub fn should_switch_to_disk(current_size: usize) -> bool {
    // Estimate memory needed for next operation:
    // current buffer + 5% expansion headroom + 64 bytes overhead
    let estimated = current_size
        .saturating_add(current_size / 20)
        .saturating_add(64);

    // Primary check: try to allocate the estimated size
    if !can_allocate(estimated) {
        return true;
    }

    // Secondary check (Linux): check /proc/meminfo
    #[cfg(target_os = "linux")]
    if let Some(available) = get_available_memory() {
        // Switch if estimated > 75% of available or < 256MB would remain
        const MIN_REMAINING: usize = 256 * 1024 * 1024; // 256 MB
        let threshold = (available * 3) / 4;
        if estimated > threshold || available.saturating_sub(estimated) < MIN_REMAINING {
            return true;
        }
    }

    false
}

/// Try to allocate the specified number of bytes to test memory availability.
fn can_allocate(size: usize) -> bool {
    let mut test_vec: Vec<u8> = Vec::new();
    test_vec.try_reserve(size).is_ok()
}

/// Get available memory from /proc/meminfo on Linux.
#[cfg(target_os = "linux")]
fn get_available_memory() -> Option<usize> {
    use std::fs;

    let content = fs::read_to_string("/proc/meminfo").ok()?;
    for line in content.lines() {
        if line.starts_with("MemAvailable:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // Value is in kB
                let kb: usize = parts[1].parse().ok()?;
                return Some(kb * 1024);
            }
        }
    }
    None
}

/// Buffer for layer-by-layer encryption/decryption data.
///
/// Supports both RAM and disk modes. In disk mode, uses two temp files
/// in a ping-pong pattern (A→B→A→B...) to reduce memory pressure.
///
/// **Memory behavior:** Disk mode reads the full data into memory for each
/// layer operation (cipher APIs require contiguous `&[u8]` input), so peak
/// memory is ~2x the data size. The benefit over RAM mode is that only one
/// layer's input and output coexist in memory at a time, and stale copies
/// are securely wiped between layers.
pub enum LayerBuffer {
    /// Data stored in RAM with automatic zeroization.
    Ram(Zeroizing<Vec<u8>>),
    /// Data stored in temp files on disk.
    Disk {
        file_a: SecureTempFile,
        file_b: SecureTempFile,
        /// If true, current data is in file_a; otherwise in file_b.
        current_is_a: bool,
    },
}

impl LayerBuffer {
    /// Create a new RAM buffer with the given data.
    pub fn new_ram(data: Vec<u8>) -> Self {
        LayerBuffer::Ram(Zeroizing::new(data))
    }

    /// Create a new disk buffer, spilling the given data to a temp file.
    pub fn switch_to_disk(data: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        let mut file_a = SecureTempFile::new()?;
        let file_b = SecureTempFile::new()?;
        file_a.write_all(&data)?;
        Ok(LayerBuffer::Disk {
            file_a,
            file_b,
            current_is_a: true,
        })
    }

    /// Check if this buffer is in disk mode.
    pub fn is_disk(&self) -> bool {
        matches!(self, LayerBuffer::Disk { .. })
    }

    /// Get the current size of the buffered data.
    pub fn len(&self) -> io::Result<usize> {
        match self {
            LayerBuffer::Ram(data) => Ok(data.len()),
            LayerBuffer::Disk {
                file_a,
                file_b,
                current_is_a,
            } => {
                let file = if *current_is_a { file_a } else { file_b };
                file.len().map(|l| l as usize)
            }
        }
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|l| l == 0)
    }

    /// Read the current data from the buffer.
    pub fn read(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        match self {
            LayerBuffer::Ram(data) => Ok(data.clone()),
            LayerBuffer::Disk {
                file_a,
                file_b,
                current_is_a,
            } => {
                let file = if *current_is_a { file_a } else { file_b };
                Ok(Zeroizing::new(file.read_all()?))
            }
        }
    }

    /// Process the data with a crypto function and store the result.
    ///
    /// For RAM mode: applies function in-place (well, replaces the buffer).
    /// For disk mode: reads from current file, applies function, writes to other file, swaps.
    ///
    /// The function `f` should return `Result<Vec<u8>, E>` where E is the crypto error type.
    /// IO errors from disk operations are returned separately.
    pub fn process<F, E>(&mut self, f: F) -> Result<(), ProcessError<E>>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        match self {
            LayerBuffer::Ram(data) => {
                let result = f(data).map_err(ProcessError::Crypto)?;
                *data = Zeroizing::new(result);
                Ok(())
            }
            LayerBuffer::Disk {
                file_a,
                file_b,
                current_is_a,
            } => {
                // Read from current file
                let (current, next) = if *current_is_a {
                    (file_a as &mut SecureTempFile, file_b as &mut SecureTempFile)
                } else {
                    (file_b as &mut SecureTempFile, file_a as &mut SecureTempFile)
                };
                let input = Zeroizing::new(current.read_all().map_err(ProcessError::Io)?);

                // Process
                let output = f(&input).map_err(ProcessError::Crypto)?;

                // Write to next file
                next.write_all(&output).map_err(ProcessError::Io)?;

                // Securely wipe stale data from the source file
                current.wipe().map_err(ProcessError::Io)?;

                // Swap
                *current_is_a = !*current_is_a;
                Ok(())
            }
        }
    }

    /// Finalize the buffer: return the data and securely delete any temp files.
    pub fn finalize(self) -> io::Result<Zeroizing<Vec<u8>>> {
        match self {
            LayerBuffer::Ram(data) => Ok(data),
            LayerBuffer::Disk {
                mut file_a,
                mut file_b,
                current_is_a,
            } => {
                let result = if current_is_a {
                    file_a.read_all()?
                } else {
                    file_b.read_all()?
                };
                // Drop triggers secure overwrite + unlink for both temp files
                drop(file_a);
                drop(file_b);
                Ok(Zeroizing::new(result))
            }
        }
    }

    /// Attempt to switch a RAM buffer to disk mode.
    /// On success, returns Ok(true) and self is now in disk mode.
    /// On failure, returns Err and self remains in RAM mode.
    /// If already in disk mode, returns Ok(false) (no-op).
    pub fn try_switch_to_disk(&mut self) -> io::Result<bool> {
        match self {
            LayerBuffer::Ram(data) => {
                let mut file_a = SecureTempFile::new()?;
                let file_b = SecureTempFile::new()?;
                file_a.write_all(data)?;
                // Take ownership of data and replace self
                let new_self = LayerBuffer::Disk {
                    file_a,
                    file_b,
                    current_is_a: true,
                };
                *self = new_self;
                Ok(true)
            }
            LayerBuffer::Disk { .. } => Ok(false),
        }
    }

    /// Explicitly switch a RAM buffer to disk mode.
    /// Returns self unchanged if already in disk mode.
    /// Consumes self - use try_switch_to_disk for in-place mutation.
    pub fn to_disk(self) -> io::Result<Self> {
        match self {
            LayerBuffer::Ram(data) => Self::switch_to_disk(data),
            disk @ LayerBuffer::Disk { .. } => Ok(disk),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_buffer_roundtrip() {
        let data = b"test data for ram buffer";
        let mut buffer = LayerBuffer::new_ram(data.to_vec());
        assert!(!buffer.is_disk());
        assert_eq!(buffer.len().unwrap(), data.len());

        let read_back = buffer.read().unwrap();
        assert_eq!(data.as_slice(), read_back.as_slice());
    }

    #[test]
    fn test_disk_buffer_roundtrip() {
        let data = b"test data for disk buffer";
        let mut buffer = LayerBuffer::switch_to_disk(Zeroizing::new(data.to_vec())).unwrap();
        assert!(buffer.is_disk());
        assert_eq!(buffer.len().unwrap(), data.len());

        let read_back = buffer.read().unwrap();
        assert_eq!(data.as_slice(), read_back.as_slice());
    }

    #[test]
    fn test_ram_process() {
        let data = b"hello";
        let mut buffer = LayerBuffer::new_ram(data.to_vec());

        buffer
            .process(|d| -> Result<Vec<u8>, io::Error> {
                Ok(d.iter().map(|b| b.wrapping_add(1)).collect())
            })
            .unwrap();

        let result = buffer.read().unwrap();
        assert_eq!(result.as_slice(), b"ifmmp");
    }

    #[test]
    fn test_disk_process() {
        let data = b"hello";
        let mut buffer = LayerBuffer::switch_to_disk(Zeroizing::new(data.to_vec())).unwrap();

        buffer
            .process(|d| -> Result<Vec<u8>, io::Error> {
                Ok(d.iter().map(|b| b.wrapping_add(1)).collect())
            })
            .unwrap();

        let result = buffer.read().unwrap();
        assert_eq!(result.as_slice(), b"ifmmp");
    }

    #[test]
    fn test_disk_pingpong() {
        let data = b"ab";
        let mut buffer = LayerBuffer::switch_to_disk(Zeroizing::new(data.to_vec())).unwrap();

        // Process multiple times to test ping-pong
        for i in 0..5 {
            buffer
                .process(|d| -> Result<Vec<u8>, io::Error> {
                    Ok(d.iter().map(|b| b.wrapping_add(1)).collect())
                })
                .unwrap();

            let expected: Vec<u8> = data.iter().map(|b| b.wrapping_add((i + 1) as u8)).collect();
            let result = buffer.read().unwrap();
            assert_eq!(result.as_slice(), expected.as_slice());
        }
    }

    #[test]
    fn test_ram_to_disk_conversion() {
        let data = b"convert me";
        let buffer = LayerBuffer::new_ram(data.to_vec());
        assert!(!buffer.is_disk());

        let mut buffer = buffer.to_disk().unwrap();
        assert!(buffer.is_disk());

        let result = buffer.read().unwrap();
        assert_eq!(data.as_slice(), result.as_slice());
    }

    #[test]
    fn test_finalize() {
        let data = b"finalize me";
        let buffer = LayerBuffer::new_ram(data.to_vec());
        let result = buffer.finalize().unwrap();
        assert_eq!(data.as_slice(), result.as_slice());

        let buffer = LayerBuffer::switch_to_disk(Zeroizing::new(data.to_vec())).unwrap();
        let result = buffer.finalize().unwrap();
        assert_eq!(data.as_slice(), result.as_slice());
    }

    #[test]
    fn test_should_switch_reasonable_size() {
        // Small sizes should not trigger switch
        assert!(!should_switch_to_disk(1024));
        assert!(!should_switch_to_disk(1024 * 1024)); // 1 MB
    }

    #[test]
    fn test_buffer_mode_parsing() {
        assert_eq!("ram".parse::<BufferMode>().unwrap(), BufferMode::Ram);
        assert_eq!("disk".parse::<BufferMode>().unwrap(), BufferMode::Disk);
        assert_eq!("auto".parse::<BufferMode>().unwrap(), BufferMode::Auto);
        assert_eq!("RAM".parse::<BufferMode>().unwrap(), BufferMode::Ram);
        assert_eq!("DISK".parse::<BufferMode>().unwrap(), BufferMode::Disk);
        assert!("invalid".parse::<BufferMode>().is_err());
    }

    #[test]
    fn test_buffer_mode_display() {
        assert_eq!(BufferMode::Ram.to_string(), "ram");
        assert_eq!(BufferMode::Disk.to_string(), "disk");
        assert_eq!(BufferMode::Auto.to_string(), "auto");
    }
}
