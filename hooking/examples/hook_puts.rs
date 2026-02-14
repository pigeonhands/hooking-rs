use std::{arch::asm, ffi::CStr};

use hooking::{HookData, HookWriter};

unsafe extern "C" fn hook(s: *const libc::c_char) {
    unsafe {
        asm!("20002:", "nop", "nop", "nop", "nop", "nop",);
    }
    let param_s = unsafe { CStr::from_ptr(s) };
    println!("puts was hooked!: Input: {:?}", param_s);
}

fn main() {
    let hook_writer = HookWriter::from_static();
    let hook = unsafe {
        hook_writer
            .write_hook(None, c"puts", hook as *mut u8)
            .unwrap()
    };
    println!("{:#?}", hook);

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

    unsafe {
        libc::puts(c"Not hooked".as_ptr());
    }
}
