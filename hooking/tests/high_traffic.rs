//! Adding and removing hooks while other threads are running hooked code, and
//! other code on the same pages, must not crash them.

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use common::{Hookable, call, for_each_writer, hook};

// `hot` is hooked once and called constantly, `neighbour` is never hooked but
// is called constantly, and the rest are hooked and unhooked repeatedly.
// Being defined together, they are likely to share pages.
hookable_functions!(
    hot = 1,
    neighbour = 2,
    f0 = 3,
    f1 = 4,
    f2 = 5,
    f3 = 6,
    f4 = 7,
    f5 = 8
);

const CALLERS: usize = 2;
const HOOKS: usize = 100;

#[test]
fn hooks_can_be_added_while_hooked_code_runs() {
    let expected_hot = call(hot::function, 2, 50) + 1;
    let expected_neighbour = call(neighbour::function, 2, 50);
    let churned: [Hookable; 6] = [
        f0::HOOKABLE,
        f1::HOOKABLE,
        f2::HOOKABLE,
        f3::HOOKABLE,
        f4::HOOKABLE,
        f5::HOOKABLE,
    ];

    // Combinations run one after another, as they all patch the same functions.
    for_each_writer(|writer| {
        let mut hot_hook = hook(writer, &hot::HOOKABLE);
        unsafe { hot_hook.apply_hook().unwrap() };

        let stop = AtomicBool::new(false);
        let calls = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..CALLERS {
                scope.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        assert_eq!(call(hot::function, 2, 50), expected_hot);
                        assert_eq!(call(neighbour::function, 2, 50), expected_neighbour);
                        calls.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }

            for target in churned.iter().cycle().take(HOOKS) {
                let mut hook = hook(writer, target);
                unsafe { hook.apply_hook().unwrap() };
                unsafe { hook.remove_hook().unwrap() };
            }
            stop.store(true, Ordering::Relaxed);
        });

        assert!(calls.load(Ordering::Relaxed) > 0);
        unsafe { hot_hook.remove_hook().unwrap() };
    });
}
