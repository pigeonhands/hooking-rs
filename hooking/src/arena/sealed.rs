use std::ptr::NonNull;

use super::{Assemble, CodeArena};
use crate::error::Result;
use crate::mem::Protection;
use crate::sys;

/// Gives each piece of code fresh read/write memory, which is made
/// read/execute once the code is copied in and never written again.
/// Executable memory never changes protection after it can be run, at the
/// cost of at least a page per hook.
#[derive(Debug)]
pub struct SealedArena;

impl SealedArena {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SealedArena {
    fn default() -> Self {
        Self::new()
    }
}

/// Copy `code` into `memory` and make it executable.
unsafe fn seal(memory: NonNull<u8>, size: usize, code: &[u8]) -> Result<()> {
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), memory.as_ptr(), code.len());
        sys::protect(memory, size, Protection::ReadExecute)?;
        sys::flush_icache(memory, code.len());
    }
    Ok(())
}

impl CodeArena for SealedArena {
    fn place(&self, near: Option<usize>, assemble: &mut Assemble) -> Result<NonNull<u8>> {
        let page_size = sys::page_size();
        let mut size = page_size;

        loop {
            let memory = unsafe { sys::alloc(size, Protection::ReadWrite, near)? };

            let code = match assemble(memory.as_ptr() as usize) {
                Ok(code) if code.len() <= size => code,
                Ok(code) => {
                    // Too big; try again with enough pages.
                    unsafe { sys::free(memory, size) };
                    size = sys::align_up(code.len(), page_size);
                    continue;
                }
                Err(err) => {
                    unsafe { sys::free(memory, size) };
                    return Err(err);
                }
            };

            if let Err(err) = unsafe { seal(memory, size, &code) } {
                unsafe { sys::free(memory, size) };
                return Err(err);
            }
            return Ok(memory);
        }
    }
}
