use std::ptr::NonNull;

use super::{PatchWriter, staged_write};
use crate::mem::{ProtectGuard, Protection, Result};
use crate::sys;

/// Makes the target's pages read/write/execute while patching, then restores
/// their original protection. The pages stay executable throughout, so other
/// code on them keeps running.
#[derive(Debug)]
pub struct ProtectPatcher;

impl ProtectPatcher {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ProtectPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchWriter for ProtectPatcher {
    unsafe fn write(&self, target: NonNull<u8>, bytes: &[u8]) -> Result<()> {
        let _guard =
            unsafe { ProtectGuard::new(target, bytes.len(), Protection::ReadWriteExecute)? };
        unsafe {
            staged_write(target, bytes, |i| target.as_ptr().add(i));
            sys::flush_icache(target, bytes.len());
        }
        Ok(())
    }
}
