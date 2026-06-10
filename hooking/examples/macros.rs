use std::ffi::CStr;

use hooking::{self, hook};

#[hook(method = "puts")]
unsafe extern "C" fn hooked_puts(s: *const i8) -> libc::c_int {
    let original_puts = unsafe {
        hooked_puts::original_function()
            .expect("hooked_puts must be invoked from hook for original_function to work")
    };

    let param_s = unsafe { CStr::from_ptr(s) };

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
