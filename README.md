hooking-rs
======

[![github-badge]][github-link]
[![crates-hooking-badge]][crates-hooking]
[![docs-hooking-badge]][docs-hooking]
![License][license-badge]

[license-badge]:https://img.shields.io/crates/l/hooking.svg?style=for-the-badge
[github-badge]: https://img.shields.io/badge/github-pigeonhands/hooking-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[github-link]: https://github.com/pigeonhands/hooking
[actions-badge]: https://img.shields.io/github/actions/workflow/status/pigeonhands/hooking/ci.yml?branch=master&style=for-the-badge
[actions-url]: https://github.com/pigeonhands/hooking/actions
[crates-hooking-badge]: https://img.shields.io/crates/v/hooking.svg?style=for-the-badge&color=fc8d62&logo=rust
[crates-hooking]: https://crates.io/crates/hooking
[docs-hooking-badge]: https://img.shields.io/badge/docs.rs-hooking-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
[docs-hooking]: https://docs.rs/hooking

Function hooking in rust
-----

A library for hooking and intercepting functions in rust for windows and linux

## Example

Each function creates a stub in memory that consists of

| Section | Description |
| ------| ------|
| Original fn detour stub address | A function pointer the generated detour stub to call the original function |
| Hooking stub | A small stub that adds some metadata (like adding detour stub address to r10 reg) before calling the hook |
| Original fn detour stub | stub that re-creates the original fn call instructions and patches the instructions to work with ling jumps, then calls the hooked function |


A simple hook:
```rust
unsafe extern "C" fn hook_destination(
    _: *mut std::ffi::c_void,
    lp_text: *const i8,
    lp_caption: *const i8,
    _: u32,
) -> i32 {
    let original_msgbox: extern "C" fn(*mut std::ffi::c_void, *const i8, *const i8, u32) -> i32 =
        unsafe { std::mem::transmute(hooking::original_function_ptr().as_ptr()) };

    original_msgbox(
        std::ptr::null_mut(),
        c"msgbox was hooked!".as_ptr(),
        c"Intercepted hook".as_ptr(),
        0,
    )
}

unsafe {
    let mut hook = Hook::by_name(
        Some(c"user32.dll"),
        c"MessageBoxA",
        hook_destination as *mut _,
    ).unwrap();

    hook.apply_hook().unwrap();
}

```

You can see more examples in the [example](https://github.com/pigeonhands/hooking-rs/tree/master/examples) directory of the repository.
