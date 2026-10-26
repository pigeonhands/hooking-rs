use crate::Hook;
use crate::error::{HookingError, Result};
use std::ffi::{CStr, c_void};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard, OnceLock};

#[derive(Debug)]
#[repr(transparent)]
pub struct MacroHook(Hook<'static>);

unsafe impl Send for MacroHook {}
unsafe impl Sync for MacroHook {}
impl DerefMut for MacroHook {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for MacroHook {
    type Target = Hook<'static>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The hook created by a `#[hook]`, set once when the program starts.
pub struct StaticHook(OnceLock<Initialized>);

struct Initialized {
    hook: Mutex<MacroHook>,
    /// Kept outside the mutex so hooks can read it without locking.
    original_function: usize,
}

impl StaticHook {
    pub const fn new() -> Self {
        Self(OnceLock::new())
    }

    fn hook(&'static self) -> Result<StaticHookGuard> {
        let initialized = self.0.get().ok_or(HookingError::NotHooked)?;
        Ok(initialized.hook.lock().unwrap())
    }
}

impl Default for StaticHook {
    fn default() -> Self {
        Self::new()
    }
}

pub type StaticHookGuard = MutexGuard<'static, MacroHook>;

pub unsafe fn init_hook(
    static_hook: &StaticHook,
    module: Option<&CStr>,
    symbol: &CStr,
    destination: *mut u8,
) {
    let hook = unsafe { Hook::by_name(module, symbol, destination).unwrap() };
    let initialized = Initialized {
        original_function: hook.original_function().as_ptr() as usize,
        hook: Mutex::new(MacroHook(hook)),
    };

    if static_hook.0.set(initialized).is_err() {
        panic!("hook {symbol:?} was initialized twice");
    }
}

pub fn original_function(static_hook: &StaticHook) -> Option<NonNull<c_void>> {
    let initialized = static_hook.0.get()?;
    NonNull::new(initialized.original_function as *mut c_void)
}

pub unsafe fn enable_hook(static_hook: &'static StaticHook) -> Result<()> {
    unsafe { static_hook.hook()?.apply_hook() }
}

pub unsafe fn disable_hook(static_hook: &'static StaticHook) -> Result<()> {
    unsafe { static_hook.hook()?.remove_hook() }
}

pub unsafe fn get_hook(static_hook: &'static StaticHook) -> Result<StaticHookGuard> {
    static_hook.hook()
}
