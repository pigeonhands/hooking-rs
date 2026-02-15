#[cfg(target_os = "windows")]
pub mod inner {
    pub mod windows;
    pub use windows::*;

    pub use windows::WindowsMemoryController as MemoryController;
}

#[cfg(target_os = "linux")]
pub mod inner {
    pub mod linux;
    pub use linux::*;

    pub use linux::LinuxMemoryController as MemoryController;
}

pub mod error;
pub mod page;
pub mod table;
use std::{
    ffi::{CStr, c_void},
    ptr::NonNull,
};

pub use error::{MemoryError, Result};
pub use table::{HeapState, HookHeap, MemoryHeapHandle, MemoryWriteHandle};

use crate::mem::page::MemoryProtectionGuard;

pub type DefaultMemoryController = inner::MemoryController;

#[derive(Debug, Clone, Copy)]
pub enum MemoryProtection {
    NoAccess,
    ReadWrite,
    ReadExecute,
    Other(usize),
}

pub trait MemoryHandle: Sized {
    fn from_ptr(ptr: NonNull<c_void>) -> Self;
    fn as_ptr(&self) -> NonNull<c_void>;
}

pub trait MemoryController {
    type Handle: MemoryHandle + Copy + Clone;
    type AllocationInfoType: AllocationInfo<Self>;

    unsafe fn get_symbol_address(
        &self,
        module: Option<&CStr>,
        symbol: &CStr,
    ) -> Result<NonNull<c_void>>;
    unsafe fn allocate_memory(&self, min_size: Option<usize>) -> Result<Self::AllocationInfoType>;
    unsafe fn set_page_protection(
        &self,
        handle: Self::Handle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<()>;

    fn protection_guard_for_page<'a>(
        &'a self,
        ptr: NonNull<c_void>,
        on_enter: MemoryProtection,
        on_exit: Option<MemoryProtection>,
    ) -> Result<MemoryProtectionGuard<'a, Self>>
    where
        Self: Sized;

    fn protection_guard<'a>(
        &'a self,
        memory_start: Self::Handle,
        memory_size: usize,
        on_enter: MemoryProtection,
        on_exit: MemoryProtection,
    ) -> Result<MemoryProtectionGuard<'a, Self>>
    where
        Self: Sized,
    {
        MemoryProtectionGuard::guard(self, on_enter, on_exit, memory_start, memory_size)
    }
}

pub trait AllocationInfo<C: MemoryController + ?Sized>: Sized {
    fn page_size(&self) -> usize;
    fn allocation_size(&self) -> usize;
    fn allocation_start(&self) -> C::Handle;
}
