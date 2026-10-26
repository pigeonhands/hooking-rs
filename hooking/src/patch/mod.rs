//! Patch writers overwrite live code in the hooked function. They must never
//! leave the target's pages non-executable, as other threads may be running
//! code on them.

use std::fmt::Debug;
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, fence};

use crate::mem::Result;

#[cfg(target_os = "linux")]
mod alias;
mod protect;

#[cfg(target_os = "linux")]
pub use alias::AliasPatcher;
pub use protect::ProtectPatcher;

#[cfg(target_os = "linux")]
pub type DefaultPatcher = AliasPatcher;
#[cfg(not(target_os = "linux"))]
pub type DefaultPatcher = ProtectPatcher;

pub trait PatchWriter: Debug + Send + Sync {
    /// Write `bytes` over the live code at `target`.
    unsafe fn write(&self, target: NonNull<u8>, bytes: &[u8]) -> Result<()>;
}

/// `jmp $` (`EB FE`) as a little endian `u16`.
const SPIN: u16 = 0xFEEB;
const CACHE_LINE: usize = 64;

/// Write `bytes` over the code at `target` so that a thread entering
/// `target` never runs a half written patch:
///
/// 1. the first two bytes become `jmp $`, so entering threads spin,
/// 2. the rest of the bytes are written,
/// 3. the first two bytes are replaced with the real ones.
///
/// Steps 1 and 3 are single stores, which x86 makes atomic as long as they
/// don't cross a cache line. When they would, the bytes are written in order.
///
/// `writable` gives the address to store the byte at each offset from
/// `target`, for patchers that write through another view of the memory.
///
/// A thread already running the overwritten instructions can still see them
/// half written; avoiding that needs every other thread suspended.
pub(crate) unsafe fn staged_write(
    target: NonNull<u8>,
    bytes: &[u8],
    writable: impl Fn(usize) -> *mut u8,
) {
    let head_crosses_cache_line = (target.as_ptr() as usize) % CACHE_LINE == CACHE_LINE - 1;
    if bytes.len() < 2 || head_crosses_cache_line {
        for (offset, &byte) in bytes.iter().enumerate() {
            unsafe { writable(offset).write_volatile(byte) };
        }
        return;
    }

    unsafe {
        store_u16(writable(0), SPIN);
        fence(Ordering::SeqCst);
        for (offset, &byte) in bytes.iter().enumerate().skip(2) {
            writable(offset).write_volatile(byte);
        }
        fence(Ordering::SeqCst);
        store_u16(writable(0), u16::from_le_bytes([bytes[0], bytes[1]]));
    }
}

/// Store `value` with a single `mov`.
unsafe fn store_u16(ptr: *mut u8, value: u16) {
    unsafe {
        core::arch::asm!(
            "mov word ptr [{ptr}], {value:x}",
            ptr = in(reg) ptr,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::{CodeArena, SealedArena};
    use crate::mem::Protection;
    use crate::sys;

    // mov eax, 1; ret
    const RETURN_1: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
    // mov eax, 2
    const SET_2: &[u8] = &[0xB8, 0x02, 0x00, 0x00, 0x00];

    /// Patch a function that returns 1 to return 2, then patch it back.
    /// Returns the patched function's address.
    fn patch_and_restore(patcher: &dyn PatchWriter) -> NonNull<u8> {
        let target = SealedArena::new()
            .place(None, &mut |_| Ok(RETURN_1.to_vec()))
            .unwrap();
        let f: extern "C" fn() -> u32 = unsafe { std::mem::transmute(target.as_ptr()) };
        assert_eq!(f(), 1);

        unsafe { patcher.write(target, SET_2).unwrap() };
        assert_eq!(f(), 2);
        assert_eq!(
            sys::query_protection(target).unwrap(),
            Protection::ReadExecute
        );

        unsafe { patcher.write(target, &RETURN_1[..SET_2.len()]).unwrap() };
        assert_eq!(f(), 1);
        target
    }

    #[test]
    fn protect_patcher() {
        patch_and_restore(&ProtectPatcher::new());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn alias_patcher_replaces_page_with_memfd() {
        let target = patch_and_restore(&AliasPatcher::new()).as_ptr() as usize;

        let page = sys::align_down(target, sys::page_size());
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let line = maps
            .lines()
            .find(|line| line.starts_with(&format!("{page:x}-")))
            .expect("patched page is mapped");
        assert!(
            line.contains(" r-xs ") && line.contains("memfd:hooking"),
            "{line}"
        );
    }

    #[test]
    fn staged_write_any_alignment() {
        let mut buf = [0u8; 3 * CACHE_LINE];
        let base = buf.as_ptr() as usize;
        let first_line = base.next_multiple_of(CACHE_LINE) - base;

        // The last offset puts the first two bytes in different cache lines.
        for line_offset in [0, CACHE_LINE - 2, CACHE_LINE - 1] {
            buf.fill(0);
            let start = first_line + line_offset;
            let target = NonNull::new(buf.as_mut_ptr().wrapping_add(start)).unwrap();
            unsafe { staged_write(target, &[1, 2, 3, 4, 5], |i| target.as_ptr().add(i)) };
            assert_eq!(&buf[start..start + 5], &[1, 2, 3, 4, 5]);
        }
    }
}
