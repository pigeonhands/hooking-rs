#![no_std]
mod hooks;
mod mem;
mod table;

pub use hooks::{Hook, HookData, HookWriter};

pub fn original_function_ptr() -> core::ptr::NonNull<core::ffi::c_void> {
    let mut orig_addr: *mut core::ffi::c_void = core::ptr::null_mut();
    unsafe {
        core::arch::asm!(
        "nop",
        lateout("r10") orig_addr,
        );

        core::ptr::NonNull::new_unchecked(orig_addr)
    }
}
