use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};

use hooking::HookWriter;
use hooking::arena::{CodeArena, DualMappedArena, SealedArena};
use hooking::patch::{PatchWriter, ProtectPatcher};

pub type BinaryFn = extern "C" fn(u64, u64) -> u64;

/// A function to hook, and a detour that calls the original function and
/// adds 1 to its result.
pub struct Hookable {
    pub function: BinaryFn,
    pub detour: BinaryFn,
    /// Where the detour finds the original function, set by `hook`.
    pub original: &'static AtomicUsize,
}

/// Defines a module for each name holding a `Hookable` that is long enough
/// to hook. Each gets its own salt so the optimizer can't merge them.
#[macro_export]
macro_rules! hookable_functions {
    ($($name:ident = $salt:literal),* $(,)?) => {
        $(
            // Not every test uses every part.
            #[allow(dead_code)]
            mod $name {
                use std::sync::atomic::{AtomicUsize, Ordering};

                use $crate::common::{BinaryFn, Hookable};

                static ORIGINAL: AtomicUsize = AtomicUsize::new(0);

                static SALT: u64 = $salt;

                /// Reads a static so that, on x86, it starts by finding its
                /// own address like position independent code does.
                #[inline(never)]
                pub extern "C" fn function(a: u64, b: u64) -> u64 {
                    let salt = *std::hint::black_box(&SALT);
                    let mut total = std::hint::black_box(a);
                    for i in 0..std::hint::black_box(b) {
                        total = total.wrapping_mul(31).wrapping_add(i ^ salt);
                    }
                    total
                }

                #[inline(never)]
                extern "C" fn add_one(a: u64, b: u64) -> u64 {
                    let original = ORIGINAL.load(Ordering::Acquire);
                    let original: BinaryFn = unsafe { std::mem::transmute(original) };
                    original(a, b) + 1
                }

                pub const HOOKABLE: Hookable = Hookable {
                    function,
                    detour: add_one,
                    original: &ORIGINAL,
                };
            }
        )*
    };
}

/// Call `f` without the compiler knowing which function it is.
pub fn call(f: BinaryFn, a: u64, b: u64) -> u64 {
    std::hint::black_box(f)(a, b)
}

/// Hook a function with its detour.
pub fn hook<'a>(writer: &HookWriter<'a>, hookable: &Hookable) -> hooking::Hook<'a> {
    let function = NonNull::new(hookable.function as *mut c_void).unwrap();
    let detour = NonNull::new(hookable.detour as *mut c_void).unwrap();
    let hook = unsafe { writer.create_hook(function, detour).unwrap() };

    let original = hook.original_function().as_ptr() as usize;
    hookable.original.store(original, Ordering::Release);
    hook
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
