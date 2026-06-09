use std::ffi::c_void;
use std::ops::{Deref, DerefMut};
use std::{ffi::CStr, sync::LazyLock};

use dashmap::DashMap;
use dashmap::mapref::one::RefMut;

use crate::Hook;
use crate::error::{HookingError, Result};

pub struct MacroHook(Hook<'static>);
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

unsafe impl Send for MacroHook {}
unsafe impl Sync for MacroHook {}

static HOOK_MAP: LazyLock<DashMap<usize, MacroHook>> = LazyLock::new(DashMap::new);

pub fn create_hook(module: Option<&CStr>, symbol: &CStr, destination: *mut u8) {
    let hook = MacroHook(unsafe { Hook::by_name(module, symbol, destination).unwrap() });
    let addr = destination as usize;
    HOOK_MAP.insert(addr, hook);
}
pub unsafe fn enable_hook(destination: *mut u8) -> Result<()> {
    let addr = destination as usize;
    let mut hook = HOOK_MAP
        .get_mut(&addr)
        .ok_or_else(|| HookingError::NotHooked(destination as *const c_void))?;

    unsafe { hook.0.apply_hook() }
}
pub unsafe fn disable_hook(destination: *mut u8) -> Result<()> {
    let addr = destination as usize;
    let mut hook = HOOK_MAP
        .get_mut(&addr)
        .ok_or_else(|| HookingError::NotHooked(destination as *const c_void))?;

    unsafe { hook.0.remove_hook() }
}

pub unsafe fn get_hook(destination: *mut u8) -> Result<RefMut<'static, usize, MacroHook>> {
    let addr = destination as usize;
    let hook = HOOK_MAP
        .get_mut(&addr)
        .ok_or_else(|| HookingError::NotHooked(destination as *const c_void))?;
    Ok(hook)
}
