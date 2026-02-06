//! Memory locking utilities to prevent sensitive data from being swapped to disk.

/// Lock a memory region to prevent it from being swapped to disk.
/// Returns true if successful, false if mlock is unavailable or fails.
/// Failure is not fatal - mlock may require elevated privileges.
#[cfg(unix)]
pub fn mlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: We're passing a valid pointer and length to mlock.
    // mlock is safe to call on any memory region we own.
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

/// Unlock a previously locked memory region.
#[cfg(unix)]
pub fn munlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: We're passing a valid pointer and length to munlock.
    unsafe { libc::munlock(ptr as *const libc::c_void, len) == 0 }
}

/// No-op on non-Unix platforms
#[cfg(not(unix))]
pub fn mlock(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// No-op on non-Unix platforms
#[cfg(not(unix))]
pub fn munlock(_ptr: *const u8, _len: usize) -> bool {
    false
}

/// A wrapper that mlocks a byte vector and munlocks on drop.
/// Combined with Zeroizing for defense in depth.
pub struct LockedVec {
    data: zeroize::Zeroizing<Vec<u8>>,
    locked: bool,
}

impl LockedVec {
    /// Create a new LockedVec, attempting to mlock the memory.
    pub fn new(data: Vec<u8>) -> Self {
        let locked = mlock(data.as_ptr(), data.len());
        Self {
            data: zeroize::Zeroizing::new(data),
            locked,
        }
    }

    /// Get a reference to the data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for LockedVec {
    fn drop(&mut self) {
        if self.locked {
            munlock(self.data.as_ptr(), self.data.len());
        }
        // Zeroizing will zero the memory on drop
    }
}

impl std::ops::Deref for LockedVec {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for LockedVec {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_vec_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let locked = LockedVec::new(data);
        assert_eq!(locked.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_empty_mlock() {
        // Should not panic on empty
        assert!(mlock(std::ptr::null(), 0));
        assert!(munlock(std::ptr::null(), 0));
    }
}
