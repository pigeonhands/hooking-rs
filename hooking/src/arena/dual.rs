use std::ptr::NonNull;
use std::sync::Mutex;

use super::{Assemble, CodeArena};
use crate::error::Result;
use crate::mem::MemoryError;
use crate::sys::{self, DualMapping};

pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct Chunk {
    map: DualMapping,
    used: usize,
}

impl Chunk {
    /// Executable address of the next free byte.
    fn cursor(&self) -> usize {
        self.map.rx.as_ptr() as usize + self.used
    }

    /// Copy `code` to the cursor, returning its executable address, or
    /// `None` if it doesn't fit.
    fn push(&mut self, code: &[u8]) -> Option<NonNull<u8>> {
        if self.used + code.len() > self.map.len {
            return None;
        }
        unsafe {
            let rw = self.map.rw.add(self.used);
            let rx = self.map.rx.add(self.used);
            std::ptr::copy_nonoverlapping(code.as_ptr(), rw.as_ptr(), code.len());
            sys::flush_icache(rx, code.len());
            self.used += code.len();
            Some(rx)
        }
    }
}

/// Maps each chunk twice: code is written through a read/write view and run
/// from a separate read/execute view of the same memory. Executable memory
/// never changes protection, so chunks are shared between hooks.
#[derive(Debug)]
pub struct DualMappedArena {
    chunks: Mutex<Vec<Chunk>>,
}

// Chunks are raw memory, only accessed under the mutex.
unsafe impl Send for DualMappedArena {}
unsafe impl Sync for DualMappedArena {}

impl DualMappedArena {
    pub const fn new() -> Self {
        Self {
            chunks: Mutex::new(Vec::new()),
        }
    }
}

impl Default for DualMappedArena {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeArena for DualMappedArena {
    fn place(&self, near: Option<usize>, assemble: &mut Assemble) -> Result<NonNull<u8>> {
        let mut chunks = self.chunks.lock().map_err(|_| MemoryError::PoisonedLock)?;

        let in_range =
            |chunk: &Chunk| near.is_none_or(|near| sys::in_rel32_range(near, chunk.cursor()));
        let mut chunk = chunks.iter().position(in_range);
        let mut needed = 0;

        loop {
            let index = match chunk {
                Some(index) => index,
                None => {
                    let size = sys::align_up(needed.max(CHUNK_SIZE), CHUNK_SIZE);
                    let map = unsafe { sys::dual_map(size, near)? };
                    chunks.push(Chunk { map, used: 0 });
                    chunks.len() - 1
                }
            };

            let code = assemble(chunks[index].cursor())?;
            if let Some(placed) = chunks[index].push(&code) {
                return Ok(placed);
            }

            // Too big for this chunk; try again in a new one that is big enough.
            needed = code.len();
            chunk = None;
        }
    }
}
