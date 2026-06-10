use std::ffi::CStr;

use hooking::{self, hook};
use libc::c_int;

#[hook(method = "puts")]
unsafe extern "C" fn hooked_puts(s: *const i8) -> c_int {
    let param_s = unsafe { CStr::from_ptr(s) };

    let original_puts: extern "C" fn(*const i8) -> c_int = unsafe {
        std::mem::transmute(
            hooking::original_function_ptr()
                .expect("called from hook")
                .as_ptr(),
        )
    };

    println!(
        "Hooked function param: {:?} | Original fn restore jump: {:?}",
        param_s, original_puts
    );

    original_puts(c"Yes, im hooked!".as_ptr())
}

fn main() {
    unsafe { hooked_puts::enable_hook().unwrap() };

    #[cfg(target_os = "linux")]
    unsafe {
        libc::puts(c"Am i hooked?".as_ptr());
    }

    unsafe { hooked_puts::disable_hook().unwrap() };

    #[cfg(target_os = "linux")]
    unsafe {
        libc::puts(c"Now im not".as_ptr());
    }
}
