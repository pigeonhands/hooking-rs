use std::{ffi::c_void, ptr::NonNull};

use super::Result;
use crate::mem::{MemoryController, MemoryHandle, MemoryProtection};

pub struct MemoryProtectionGuard<'a, M: MemoryController> {
    on_exit: MemoryProtection,
    memory_start: M::Handle,
    memory_size: usize,
    mem: &'a M,
}

impl<'a, M: MemoryController> MemoryProtectionGuard<'a, M> {
    pub fn guard(
        mem: &'a M,
        on_enter: MemoryProtection,
        on_exit: MemoryProtection,
        memory_start: M::Handle,
        memory_size: usize,
    ) -> Result<Self> {
        let mut guard = Self {
            mem,
            on_exit,
            memory_start,
            memory_size,
        };
        unsafe {
            guard.set_page_protection(on_enter)?;
        }
        Ok(guard)
    }

    unsafe fn set_page_protection(&mut self, protection: MemoryProtection) -> Result<()> {
        unsafe {
            self.mem
                .set_page_protection(self.memory_start, self.memory_size, protection)
        }
    }

    pub fn as_ptr(&self) -> NonNull<c_void> {
        self.memory_start.as_ptr()
    }
}

impl<'a, M: MemoryController> Drop for MemoryProtectionGuard<'a, M> {
    fn drop(&mut self) {
        unsafe {
            self.set_page_protection(self.on_exit).unwrap();
        }
    }
}
