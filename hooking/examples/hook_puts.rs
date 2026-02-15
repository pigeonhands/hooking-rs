use hooking::Hook;
pub use hooking::{HookData, HookWriter};
pub use std::{arch::asm, ffi::CStr};

unsafe extern "C" fn hooked_puts(s: *const i8) {
    let param_s = unsafe { CStr::from_ptr(s) };

    let original_puts: extern "C" fn(*const i8) =
        unsafe { std::mem::transmute(hooking::original_function_ptr().as_ptr()) };

    println!(
        "Hooked function param: {:?} | Original fn restore jump: {:?}",
        param_s, original_puts
    );

    original_puts(c"Call original puts restore detour".as_ptr());
}

fn main() {
    let mut hook = unsafe { Hook::by_name(None, c"puts", hooked_puts as *mut u8).unwrap() };

    unsafe {
        hook.apply_hook().unwrap();
    }

    #[cfg(target_os = "linux")]
    unsafe {
        libc::puts(c"Am i hooked?".as_ptr());
    }
}
