//! Platform primitives. Each platform module exposes the same set of free
//! functions; everything built on top of them lives outside this module.

use std::ptr::NonNull;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

/// How far a rel32 operand reaches, less 1MB of slack so that code placed
/// right after an in-range address is also in range.
const REL32_REACH: usize = 0x7FF0_0000;

/// The same memory mapped twice: once writable, once executable.
#[derive(Debug)]
pub struct DualMapping {
    pub rw: NonNull<u8>,
    pub rx: NonNull<u8>,
    pub len: usize,
}

pub const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

pub const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// The page-aligned start and length of the pages covering `[ptr, ptr + len)`.
pub fn page_range(ptr: usize, len: usize) -> (usize, usize) {
    let page_size = page_size();
    let start = align_down(ptr, page_size);
    let end = align_up(ptr + len.max(1), page_size);
    (start, end - start)
}

/// Whether `to` can be reached from `from` with a rel32 offset.
pub fn in_rel32_range(from: usize, to: usize) -> bool {
    // On 32bit, rel32 offsets wrap around and reach every address.
    cfg!(target_pointer_width = "32") || from.abs_diff(to) < REL32_REACH
}

/// Addresses within rel32 range of `near`, `step` apart, moving outwards
/// from it alternately up and down.
fn near_candidates(near: usize, step: usize) -> impl Iterator<Item = usize> {
    let base = align_down(near, step);
    (1..REL32_REACH / step)
        .flat_map(move |i| [base.checked_add(i * step), base.checked_sub(i * step)])
        .flatten()
        .filter(move |&addr| addr != 0 && in_rel32_range(near, addr))
}
