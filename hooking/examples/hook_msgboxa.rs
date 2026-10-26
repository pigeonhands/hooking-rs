use hooking::Hook;
use std::ffi::CStr;
use std::sync::OnceLock;

#[link(name = "user32")]
unsafe extern "system" {
    unsafe fn MessageBoxA(
        hWnd: *mut std::ffi::c_void,
        lpText: *const i8,
        lpCaption: *const i8,
        uType: u32,
    ) -> i32;
}

// MessageBoxA is stdcall on x86, so the hook and the original must be
// "system" too.
type MessageBoxFn = extern "system" fn(*mut std::ffi::c_void, *const i8, *const i8, u32) -> i32;

/// The original MessageBoxA, set once the hook has been created.
static ORIGINAL_MSGBOX: OnceLock<MessageBoxFn> = OnceLock::new();

unsafe extern "system" fn hook_destination(
    _: *mut std::ffi::c_void,
    lp_text: *const i8,
    lp_caption: *const i8,
    _: u32,
) -> i32 {
    let original_msgbox = ORIGINAL_MSGBOX
        .get()
        .expect("set before the hook is applied");

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
    let original: MessageBoxFn = unsafe { std::mem::transmute(hook.original_function().as_ptr()) };
    ORIGINAL_MSGBOX.set(original).unwrap();

    println!("Applying hook");

    unsafe {
        hook.apply_hook().unwrap();
        MessageBoxA(
            std::ptr::null_mut(),
            c"Am i hooked?".as_ptr(),
            c"hooked-rs".as_ptr(),
            0,
        );
    }

    unsafe {
        hook.remove_hook().unwrap();
        MessageBoxA(
            std::ptr::null_mut(),
            c"Not hooked anymore".as_ptr(),
            c"hooked-rs".as_ptr(),
            0,
        );
    }
}
