pub use hooking::{HookData, HookWriter};
pub use std::{arch::asm, ffi::CStr};

unsafe extern "C" fn hook(s: *const i8) {
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
    let hook_writer = HookWriter::from_static();
    let hook = unsafe {
        hook_writer
            .create_hook_by_name(Some(c"libc"), c"puts", hook as *mut u8)
            .unwrap()
    };

    let HookData {
        trampoline_data, ..
    } = hook.data;

    unsafe {
        asm! {
            "mov rdi, {}",
            "call {}",
            in(reg)c"Call trampoline hook manually".as_ptr(),
            in(reg)trampoline_data.as_ptr()
        }
    }

    #[cfg(target_os = "linux")]
    unsafe {
        libc::puts(c"Not hooked".as_ptr());
    }
}
