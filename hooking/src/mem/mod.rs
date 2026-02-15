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

pub mod table;
use std::{
    ffi::{CStr, c_void},
    ptr::NonNull,
};

pub use error::{MemoryError, Result};
pub use table::{HeapState, HookHeap, MemoryHeapHandle, MemoryWriteHandle};

pub type DefaultMemoryController = inner::MemoryController;

#[derive(Debug, Clone, Copy)]
pub enum MemoryProtection {
    NoAccess,
    ReadWrite,
    ReadExecute,
}

pub trait MemoryHandle: Sized {
    fn as_ptr(&self) -> NonNull<c_void>;
}

pub trait MemoryController {
    type Handle: MemoryHandle;
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
}

pub trait AllocationInfo<C: MemoryController + ?Sized>: Sized {
    fn page_size(&self) -> usize;
    fn allocation_size(&self) -> usize;
    fn allocation_start(&self) -> C::Handle;
}
