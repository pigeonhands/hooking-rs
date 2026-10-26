mod common;

use common::{call, for_each_writer, hook};

hookable_functions!(target = 1);

#[test]
fn hooks_apply_and_remove() {
    let expected = call(target, 3, 10);

    // Combinations run one after another, as they all patch `target`.
    for_each_writer(|writer| {
        let mut hook = hook(writer, target);
        assert_eq!(call(target, 3, 10), expected, "not applied yet");

        unsafe { hook.apply_hook().unwrap() };
        assert_eq!(call(target, 3, 10), expected + 1);

        unsafe { hook.remove_hook().unwrap() };
        assert_eq!(call(target, 3, 10), expected);
    });

    let detour = common::add_one_detour as *mut u8;
    let mut hook = unsafe { hooking::Hook::create(target as *mut u8, detour).unwrap() };
    unsafe { hook.apply_hook().unwrap() };
    assert_eq!(call(target, 3, 10), expected + 1, "default writer");
    unsafe { hook.remove_hook().unwrap() };
}
