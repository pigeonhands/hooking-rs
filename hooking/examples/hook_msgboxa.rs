use hooking::Hook;
use std::ffi::CStr;

#[link(name = "user32")]
unsafe extern "system" {
    unsafe fn MessageBoxA(
        hWnd: *mut std::ffi::c_void,
        lpText: *const i8,
        lpCaption: *const i8,
        uType: u32,
    ) -> i32;
}

unsafe extern "C" fn hook_destination(
    _: *mut std::ffi::c_void,
    lp_text: *const i8,
    lp_caption: *const i8,
    _: u32,
) -> i32 {
    let original_msgbox: extern "C" fn(*mut std::ffi::c_void, *const i8, *const i8, u32) -> i32 =
        unsafe { std::mem::transmute(hooking::original_function_ptr().as_ptr()) };

    println!(
        "Called with title: {:?} | Body: {:?}",
        unsafe { CStr::from_ptr(lp_text) },
        unsafe { CStr::from_ptr(lp_caption) }
    );

    original_msgbox(
        std::ptr::null_mut(),
        c"msgbox was hooked!".as_ptr(),
        c"Intercepted hook".as_ptr(),
        0,
    )
}

fn main() {
    let mut hook = unsafe {
        Hook::by_name(
            Some(c"user32.dll"),
            c"MessageBoxA",
            hook_destination as *mut _,
        )
        .unwrap()
    };

    println!("Applying hook");
    hook.apply_hook().unwrap();

    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            c"Am i hooked?".as_ptr(),
            c"hooked-rs".as_ptr(),
            0,
        );
    }

    hook.remove_hook().unwrap();
    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            c"Not hooked anymore".as_ptr(),
            c"hooked-rs".as_ptr(),
            0,
        );
    }
}
