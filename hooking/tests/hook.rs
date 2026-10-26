mod common;

use common::{call, for_each_writer, hook};

hookable_functions!(target = 1);

#[test]
fn hooks_apply_and_remove() {
    let expected = call(target::function, 3, 10);

    // Combinations run one after another, as they all patch `target`.
    for_each_writer(|writer| {
        let mut hook = hook(writer, &target::HOOKABLE);
        assert_eq!(call(target::function, 3, 10), expected, "not applied yet");

        unsafe { hook.apply_hook().unwrap() };
        assert_eq!(call(target::function, 3, 10), expected + 1);

        unsafe { hook.remove_hook().unwrap() };
        assert_eq!(call(target::function, 3, 10), expected);
    });
}

/// The trampoline passes the original function in registers on x86_64.
#[cfg(target_arch = "x86_64")]
mod original_function_ptr {
    use super::common::{BinaryFn, call};

    crate::hookable_functions!(target = 2);

    #[inline(never)]
    extern "C" fn detour(a: u64, b: u64) -> u64 {
        let original = hooking::original_function_ptr().expect("called from the hook");
        let original: BinaryFn = unsafe { std::mem::transmute(original.as_ptr()) };
        original(a, b) + 1
    }

    #[test]
    fn reaches_the_original_function() {
        let expected = call(target::function, 3, 10);
        let function = target::function as *mut u8;
        let mut hook = unsafe { hooking::Hook::create(function, detour as *mut u8).unwrap() };

        unsafe { hook.apply_hook().unwrap() };
        assert_eq!(call(target::function, 3, 10), expected + 1);
        unsafe { hook.remove_hook().unwrap() };
    }

    #[test]
    fn is_none_outside_a_hook() {
        assert!(hooking::original_function_ptr().is_none());
    }
}

/// Position independent x86 code finds its own address through a call, and
/// must still see its original address once relocated.
#[cfg(target_arch = "x86")]
mod pc_capture {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hooking::arena::{CodeArena, SealedArena};

    type AddressFn = extern "C" fn() -> usize;

    /// Returns its own address:
    ///     call $+5
    ///     pop eax
    ///     sub eax, 5
    ///     ret
    const CALL_NEXT: &[u8] = &[0xE8, 0, 0, 0, 0, 0x58, 0x83, 0xE8, 0x05, 0xC3];

    /// A `__x86.get_pc_thunk.ax`, then a function returning its own address:
    /// thunk:
    ///     mov eax, [esp]
    ///     ret
    /// function:
    ///     call thunk
    ///     sub eax, 5
    ///     ret
    const CALL_THUNK: &[u8] = &[
        0x8B, 0x04, 0x24, 0xC3, // thunk
        0xE8, 0xF7, 0xFF, 0xFF, 0xFF, 0x83, 0xE8, 0x05, 0xC3, // function
    ];
    const CALL_THUNK_FUNCTION_OFFSET: usize = 4;

    static ORIGINAL: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn detour() -> usize {
        let original: AddressFn = unsafe { std::mem::transmute(ORIGINAL.load(Ordering::Acquire)) };
        original()
    }

    fn assert_original_sees_its_address(code: &[u8], function_offset: usize) {
        let arena = SealedArena::new();
        let placed = arena.place(None, &mut |_| Ok(code.to_vec())).unwrap();
        let function = unsafe { placed.add(function_offset) };
        let call: AddressFn = unsafe { std::mem::transmute(function.as_ptr()) };
        assert_eq!(call(), function.as_ptr() as usize);

        let mut hook =
            unsafe { hooking::Hook::create(function.as_ptr(), detour as *mut u8).unwrap() };
        let original = hook.original_function().as_ptr() as usize;
        ORIGINAL.store(original, Ordering::Release);

        unsafe { hook.apply_hook().unwrap() };
        assert_eq!(call(), function.as_ptr() as usize, "through the hook");
        unsafe { hook.remove_hook().unwrap() };
    }

    // One test, as both use `ORIGINAL`.
    #[test]
    fn relocated_code_sees_original_address() {
        assert_original_sees_its_address(CALL_NEXT, 0);
        assert_original_sees_its_address(CALL_THUNK, CALL_THUNK_FUNCTION_OFFSET);
    }
}
