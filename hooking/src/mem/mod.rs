pub mod error;

use std::ptr::NonNull;

pub use error::{MemoryError, Result};

use crate::sys;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    NoAccess,
    Read,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
    /// A platform specific protection value.
    Native(usize),
}

/// Changes the protection of every page covering a byte range and restores
/// each page's original protection when dropped.
pub struct ProtectGuard {
    page_size: usize,
    original: Vec<(NonNull<u8>, Protection)>,
}

impl ProtectGuard {
    pub unsafe fn new(ptr: NonNull<u8>, len: usize, protection: Protection) -> Result<Self> {
        let page_size = sys::page_size();
        let (start, range_len) = sys::page_range(ptr.as_ptr() as usize, len);

        let mut guard = Self {
            page_size,
            original: Vec::with_capacity(range_len / page_size),
        };

        for page in (start..start + range_len).step_by(page_size) {
            let page =
                NonNull::new(page as *mut u8).ok_or(MemoryError::BadAdress(ptr.as_ptr().cast()))?;
            let original = sys::query_protection(page)?;
            unsafe { sys::protect(page, page_size, protection)? };
            // Pushed only once changed, so a failure part way restores just these.
            guard.original.push((page, original));
        }

        Ok(guard)
    }
}

impl Drop for ProtectGuard {
    fn drop(&mut self) {
        for &(page, protection) in &self.original {
            // Nothing useful can be done with a failure while dropping.
            let _ = unsafe { sys::protect(page, self.page_size, protection) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_covers_page_crossing_range_and_restores() {
        let page_size = sys::page_size();
        let pages = unsafe { sys::alloc(2 * page_size, Protection::ReadExecute, None).unwrap() };
        let second = unsafe { pages.add(page_size) };
        unsafe { sys::protect(second, page_size, Protection::Read).unwrap() };

        // Two bytes either side of the page boundary.
        let ptr = unsafe { pages.add(page_size - 2) };
        {
            let _guard =
                unsafe { ProtectGuard::new(ptr, 4, Protection::ReadWriteExecute).unwrap() };
            assert_eq!(
                sys::query_protection(pages).unwrap(),
                Protection::ReadWriteExecute
            );
            assert_eq!(
                sys::query_protection(second).unwrap(),
                Protection::ReadWriteExecute
            );
            unsafe { ptr.as_ptr().write_bytes(0xCC, 4) };
        }

        // Each page gets its own original protection back.
        assert_eq!(
            sys::query_protection(pages).unwrap(),
            Protection::ReadExecute
        );
        assert_eq!(sys::query_protection(second).unwrap(), Protection::Read);
        unsafe { sys::free(pages, 2 * page_size) };
    }
}
