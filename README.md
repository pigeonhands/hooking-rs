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

A library for hooking and intercepting functions in rust for windows and linux, on x86_64 and x86.

## Arenas and patchers

Creating or applying a hook never makes code that may be running non-executable, so hooks
can be added and removed while hooked functions are being called on other threads.

Where the generated hook code lives is chosen by a `CodeArena`:

| Arena | Description |
| ------| ------|
| `DualMappedArena` (default) | Maps memory twice, writable and executable. Hooks are written through the writable view, so executable memory never changes protection and hooks share pages. |
| `SealedArena` | Each hook gets fresh memory that is made executable once and never written again. Uses at least a page per hook. |

How the jump is written into the hooked function is chosen by a `PatchWriter`:

| Patcher | Description |
| ------| ------|
| `AliasPatcher` (default on linux) | Swaps the target's pages for an identical memfd-backed copy with a writable alias, then patches through the alias. Protection never changes. |
| `ProtectPatcher` (default on windows) | Makes the target's pages read/write/execute while patching, then restores their original protection. |

```rust
use hooking::{HookWriter, arena::SealedArena, patch::ProtectPatcher};

static ARENA: SealedArena = SealedArena::new();
static PATCHER: ProtectPatcher = ProtectPatcher::new();

let writer = HookWriter::new(&ARENA).with_patcher(&PATCHER);
let mut hook = unsafe { writer.create_hook(target, destination)? };
unsafe { hook.apply_hook()? };
```

## Example

Each function creates a stub in memory that consists of

| Section | Description |
| ------| ------|
| Original fn detour stub address | A function pointer the generated detour stub to call the original function |
| Hooking stub | A small stub that jumps to the hook. On x86_64 it first passes the original fn detour stub address in r10, for `original_function_ptr` |
| Original fn detour stub | stub that re-creates the original fn call instructions and patches the instructions to work with ling jumps, then calls the hooked function |


A simple hook:

```rust
// MessageBoxA is stdcall on x86, so the hook must be "system" too.
#[hook(lib = "user32.dll", method = "MessageBoxA")]
unsafe extern "system" fn hook_destination(
    _: *mut std::ffi::c_void,
    lp_text: *const i8,
    lp_caption: *const i8,
    _: u32,
) -> i32 {
    let original_msgbox = unsafe {
        hook_destination::original_function().expect("the hook was created")
    };

    original_msgbox(
        std::ptr::null_mut(),
        c"msgbox was hooked!".as_ptr(),
        c"Intercepted hook".as_ptr(),
        0,
    )
}

unsafe { hook_destination::enable_hook().unwrap() };

```

Without the macro, `Hook::original_function` gives the original function, which the hook
can read from wherever it was stored. On x86_64, `hooking::original_function_ptr()` also
returns it from inside the hook, as long as it is called before anything else in the hook.
x86 passes arguments on the stack, so it has no register to spare for this.

You can see more examples in the [example](https://github.com/pigeonhands/hooking-rs/tree/master/examples) directory of the repository.
