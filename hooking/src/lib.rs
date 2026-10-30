pub mod arena;
pub mod asm;
pub mod error;
pub mod hooks;
pub mod mem;
pub mod patch;
mod sys;

cfg_select! {
    feature = "macros" => {
        mod macros;

        pub use hooking_macros::hook;
        pub mod __macro_support {
            pub use super::macros::*;
        }
    }
    _ => {}
}

pub use hooks::{Hook, HookData, HookWriter};

#[cfg(target_arch = "x86_64")]
pub use hooks::{
    CallResult, DispatchResult, HookAction, SavedRegs, SavedRegsDispatch,
    call_with_saved_regs,
};

#[cfg(target_arch = "x86_64")]
pub(crate) const ORIGINAL_FN_CHECKSUM_MAGIC: usize = 0xDEADBEEFCAFEBABE;

/// The original function of the hook currently running, which its trampoline
/// passes in r10, with a checksum of it in r11. Returns `None` when not
/// called from a hook.
///
/// It must be called at the very start of the hook, before anything else
/// uses those registers. Only x86_64 has registers to spare for this; on any
/// architecture, [`Hook::original_function`] gives a hook's original function.
#[cfg(target_arch = "x86_64")]
pub fn original_function_ptr() -> Option<core::ptr::NonNull<core::ffi::c_void>> {
    let mut orig_addr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut checksum = 0usize;
    unsafe {
        core::arch::asm!(
        "nop",
        lateout("r10") orig_addr,
        lateout("r11") checksum,
        );

        ((orig_addr as usize ^ ORIGINAL_FN_CHECKSUM_MAGIC) == checksum)
            .then(|| core::ptr::NonNull::new_unchecked(orig_addr))
    }
}
