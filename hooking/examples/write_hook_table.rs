use core::ptr::NonNull;
use std::sync::OnceLock;

use hooking::{HookData, HookWriter};

type AddFn = extern "C" fn(a: i32, b: i32) -> i32;

/// The original `add_two_numbers_together`, set once the hook has been created.
static ORIGINAL_ADD: OnceLock<AddFn> = OnceLock::new();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn add_two_numbers_together(a: i32, b: i32) -> i32 {
    println!("adding {a} + {b}");
    a + b
}

unsafe extern "C" fn hook(a: i32, b: i32) -> i32 {
    let original_add = ORIGINAL_ADD.get().expect("set before the hook is called");

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
    let original: AddFn = unsafe { std::mem::transmute(hook.original_function().as_ptr()) };
    ORIGINAL_ADD.set(original).unwrap();

    let HookData {
        trampoline_data, ..
    } = hook.data;

    println!("about to run hook");

    // The hook isn't applied, so call its trampoline directly.
    let trampoline: AddFn = unsafe { std::mem::transmute(trampoline_data.as_ptr()) };
    trampoline(6, 7);
}
