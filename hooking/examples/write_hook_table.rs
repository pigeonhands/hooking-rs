use std::arch::asm;

use core::ptr::NonNull;
use hooking::{HookData, HookWriter};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn add_two_numbers_together(a: i32, b: i32) -> i32 {
    println!("adding {a} + {b}");
    a + b
}

unsafe extern "C" fn hook(a: i32, b: i32) -> i32 {
    let original_add: extern "C" fn(a: i32, b: i32) -> i32 =
        unsafe { std::mem::transmute(hooking::original_function_ptr().as_ptr()) };

    println!("Hooked with params: ({a}, {b})");

    original_add(5, 6)
}

fn main() {
    let hook_writer = HookWriter::from_static();
    let hook = unsafe {
        hook_writer
            .create_hook(
                NonNull::new(add_two_numbers_together as *mut _).unwrap(),
                NonNull::new(hook as *mut _).unwrap(),
            )
            .unwrap()
    };

    let HookData {
        trampoline_data, ..
    } = hook.data;

    println!("about to run hook");

    unsafe {
        #[cfg(target_os = "linux")]
        asm! {
            "mov rdi, 6",
            "mov rsi, 7",
            "call {}",
            in(reg)trampoline_data.as_ptr()
        }
        #[cfg(target_os = "windows")]
        asm! {
            "mov rcx, 6",
            "mov rdx, 7",
            "call {}",
            in(reg)trampoline_data.as_ptr()
        }
    }
}
