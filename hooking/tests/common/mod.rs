use std::ffi::c_void;
use std::ptr::NonNull;

use hooking::HookWriter;
use hooking::arena::{CodeArena, DualMappedArena, SealedArena};
use hooking::patch::{PatchWriter, ProtectPatcher};

pub type BinaryFn = extern "C" fn(u64, u64) -> u64;

/// Defines `extern "C" fn(u64, u64) -> u64` functions that are long enough
/// to hook. Each gets its own salt so the optimizer can't merge them.
#[macro_export]
macro_rules! hookable_functions {
    ($($name:ident = $salt:literal),* $(,)?) => {
        $(
            #[inline(never)]
            extern "C" fn $name(a: u64, b: u64) -> u64 {
                let mut total = std::hint::black_box(a);
                for i in 0..std::hint::black_box(b) {
                    total = total.wrapping_mul(31).wrapping_add(i ^ $salt);
                }
                total
            }
        )*
    };
}

/// Calls the original function and adds 1 to its result.
#[inline(never)]
pub extern "C" fn add_one_detour(a: u64, b: u64) -> u64 {
    let original = hooking::original_function_ptr().expect("called from the hook");
    let original: BinaryFn = unsafe { std::mem::transmute(original.as_ptr()) };
    original(a, b) + 1
}

/// Call `f` without the compiler knowing which function it is.
pub fn call(f: BinaryFn, a: u64, b: u64) -> u64 {
    std::hint::black_box(f)(a, b)
}

/// Hook `target` with `add_one_detour`.
pub fn hook<'a>(writer: &HookWriter<'a>, target: BinaryFn) -> hooking::Hook<'a> {
    let target = NonNull::new(target as *mut c_void).unwrap();
    let detour = NonNull::new(add_one_detour as *mut c_void).unwrap();
    unsafe { writer.create_hook(target, detour).unwrap() }
}

/// Run `f` with a writer for every arena and patcher, one after another.
pub fn for_each_writer(mut f: impl FnMut(&HookWriter)) {
    let arenas: [&dyn CodeArena; 2] = [&DualMappedArena::new(), &SealedArena::new()];

    let protect = ProtectPatcher::new();
    #[cfg(target_os = "linux")]
    let alias = hooking::patch::AliasPatcher::new();
    let patchers: &[&dyn PatchWriter] = &[
        &protect,
        #[cfg(target_os = "linux")]
        &alias,
    ];

    for arena in arenas {
        for &patcher in patchers {
            f(&HookWriter::new(arena).with_patcher(patcher));
        }
    }
}
