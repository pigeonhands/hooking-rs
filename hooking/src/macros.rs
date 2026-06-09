use crate::Hook;
use crate::error::{HookingError, Result};
use std::ffi::CStr;
use std::ops::{Deref, DerefMut};
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

pub type StaticHook = OnceLock<Mutex<MacroHook>>;
pub type StaticHookGuard = MutexGuard<'static, MacroHook>;

pub unsafe fn init_hook(
    static_hook: &StaticHook,
    module: Option<&CStr>,
    symbol: &CStr,
    destination: *mut u8,
) {
    let hook = unsafe { Hook::by_name(module, symbol, destination).unwrap() };

    static_hook.set(Mutex::new(MacroHook(hook))).unwrap();
}
pub unsafe fn enable_hook(static_hook: &StaticHook) -> Result<()> {
    let mut hook = static_hook
        .get()
        .ok_or_else(|| HookingError::NotHooked)?
        .lock()
        .unwrap();

    unsafe { hook.apply_hook() }
}
pub unsafe fn disable_hook(static_hook: &StaticHook) -> Result<()> {
    let mut hook = static_hook
        .get()
        .ok_or_else(|| HookingError::NotHooked)?
        .lock()
        .unwrap();

    unsafe { hook.remove_hook() }
}
pub unsafe fn get_hook(static_hook: &'static StaticHook) -> Result<StaticHookGuard> {
    let hook = static_hook
        .get()
        .ok_or_else(|| HookingError::NotHooked)?
        .lock()
        .unwrap();

    Ok(hook)
}
