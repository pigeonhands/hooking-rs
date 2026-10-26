use std::ptr::NonNull;
use std::sync::Mutex;

use super::{PatchWriter, staged_write};
use crate::mem::{MemoryError, Result};
use crate::sys;

/// A writable view of one page of code.
#[derive(Debug)]
struct Alias {
    page: usize,
    rw: NonNull<u8>,
}

/// Patches through a second, writable view of the target's pages, so their
/// protection never changes.
///
/// The first patch to a page swaps it for a memfd-backed copy (same bytes,
/// same protection) that also has a writable view. Later patches to that
/// page, including removing the hook, go straight through that view.
///
/// Caveats:
/// - A swapped page is no longer file-backed, so `/proc/self/maps` shows it
///   as `memfd:hooking` and debuggers/profilers may not symbolize it.
/// - Nothing else may write to the page while it is being swapped.
#[derive(Debug)]
pub struct AliasPatcher {
    aliases: Mutex<Vec<Alias>>,
}

// Aliases are raw memory, only accessed under the mutex.
unsafe impl Send for AliasPatcher {}
unsafe impl Sync for AliasPatcher {}

impl AliasPatcher {
    pub const fn new() -> Self {
        Self {
            aliases: Mutex::new(Vec::new()),
        }
    }
}

impl Default for AliasPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchWriter for AliasPatcher {
    unsafe fn write(&self, target: NonNull<u8>, bytes: &[u8]) -> Result<()> {
        let mut aliases = self.aliases.lock().map_err(|_| MemoryError::PoisonedLock)?;
        let page_size = sys::page_size();
        let (start, len) = sys::page_range(target.as_ptr() as usize, bytes.len());

        // Each page is aliased separately, as neighbouring pages can have
        // different protections.
        for page in (start..start + len).step_by(page_size) {
            if aliases.iter().any(|alias| alias.page == page) {
                continue;
            }
            let page_ptr =
                NonNull::new(page as *mut u8).expect("pages of a valid pointer are not null");
            let rw = unsafe { sys::alias_pages(page_ptr, page_size)? };
            aliases.push(Alias { page, rw });
        }

        let writable = |offset: usize| {
            let addr = target.as_ptr() as usize + offset;
            let page = sys::align_down(addr, page_size);
            let alias = aliases
                .iter()
                .find(|alias| alias.page == page)
                .expect("every page in range was aliased");
            unsafe { alias.rw.as_ptr().add(addr - page) }
        };

        unsafe {
            staged_write(target, bytes, writable);
            sys::flush_icache(target, bytes.len());
        }
        Ok(())
    }
}
