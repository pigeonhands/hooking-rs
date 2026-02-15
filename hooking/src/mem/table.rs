use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard};

use crate::mem::{AllocationInfo, DefaultMemoryController, MemoryHandle, MemoryProtection};

use super::MemoryController;
use super::{MemoryError, Result};

#[derive(Debug)]
pub struct HeapState<C: MemoryController> {
    allocation: Option<C::AllocationInfoType>,
    written: usize,
}

impl<C: MemoryController> HeapState<C> {
    pub const fn empty() -> Self {
        Self {
            allocation: None,
            written: 0,
        }
    }

    pub unsafe fn ensure_allocated(&mut self, mem: &C, min_size: Option<usize>) -> Result<()> {
        if self.allocation.is_none() {
            self.allocation = Some(unsafe { mem.allocate_memory(min_size)? });
        }
        Ok(())
    }

    fn allocation(&self) -> Result<&C::AllocationInfoType> {
        match &self.allocation {
            Some(allocation) => Ok(allocation),
            None => Err(MemoryError::TableHeapNotAllocated),
        }
    }
}

pub struct HookHeap<C: MemoryController> {
    pub mem: C,
    state: Mutex<HeapState<C>>,
}
unsafe impl<C: MemoryController> Send for HookHeap<C> where C: Send {}
unsafe impl<C: MemoryController> Sync for HookHeap<C> where C: Sync {}

impl HookHeap<DefaultMemoryController> {
    pub const fn new() -> Self {
        Self::with_memory_controller(DefaultMemoryController::new())
    }
}

impl<C: MemoryController> HookHeap<C> {
    pub const fn with_memory_controller(controller: C) -> Self {
        Self {
            mem: controller,
            state: Mutex::new(HeapState::empty()),
        }
    }

    fn state<'a>(&'a self) -> Result<MutexGuard<'a, HeapState<C>>> {
        self.state
            .lock()
            .map_err(|_| MemoryError::BadTableHeapState)
    }

    pub unsafe fn ensure_allocated(&self, min_size: Option<usize>) -> Result<()> {
        unsafe { self.state()?.ensure_allocated(&self.mem, min_size) }
    }

    pub fn get_handle<'a>(&'a self) -> Result<MemoryHeapHandle<'a, C>> {
        let mut state = self.state()?;
        unsafe {
            state.ensure_allocated(&self.mem, None)?;
        }

        Ok(MemoryHeapHandle {
            state,
            mem: &self.mem,
        })
    }
}

pub struct MemoryHeapHandle<'a, C: MemoryController> {
    state: MutexGuard<'a, HeapState<C>>,
    mem: &'a C,
}

impl<'a, C: MemoryController> MemoryHeapHandle<'a, C> {
    pub fn begin_write(&mut self) -> Result<MemoryWriteHandle<'a, '_, C>> {
        MemoryWriteHandle::new_from(self)
    }

    pub unsafe fn write_address(&self) -> Result<NonNull<c_void>> {
        let allocation = self.state.allocation()?;
        Ok(unsafe {
            allocation
                .allocation_start()
                .as_ptr()
                .add(self.state.written)
        })
    }

    pub unsafe fn reserve(&mut self, size: usize) -> Result<NonNull<c_void>> {
        let allocation = self.state.allocation()?;

        if self.state.written + size > allocation.allocation_size() {
            return Err(MemoryError::NoMemory {
                needs: self.state.written + size,
                has: allocation.allocation_size(),
            });
        }

        let write_address = unsafe {
            allocation
                .allocation_start()
                .as_ptr()
                .add(self.state.written)
        };

        self.state.written += size;

        Ok(write_address)
    }

    unsafe fn set_page_protection(&mut self, protection: MemoryProtection) -> Result<()> {
        let allocation = self.state.allocation()?;
        unsafe {
            self.mem.set_page_protection(
                allocation.allocation_start(),
                allocation.allocation_size(),
                protection,
            )
        }
    }

    pub unsafe fn make_writable(&mut self) -> Result<()> {
        unsafe { self.set_page_protection(MemoryProtection::ReadWrite) }
    }

    pub unsafe fn make_executable(&mut self) -> Result<()> {
        unsafe { self.set_page_protection(MemoryProtection::ReadExecute) }
    }
}

pub struct MemoryWriteHandle<'a, 'b, C: MemoryController> {
    heap: &'b mut MemoryHeapHandle<'a, C>,
}

impl<'a, 'b, C: MemoryController> MemoryWriteHandle<'a, 'b, C> {
    pub fn new_from(state: &'b mut MemoryHeapHandle<'a, C>) -> Result<Self> {
        let handle = Self { heap: state };

        unsafe {
            handle.heap.make_writable()?;
        }

        Ok(handle)
    }

    pub unsafe fn write_address(&self) -> Result<NonNull<c_void>> {
        unsafe { self.heap.write_address() }
    }

    pub unsafe fn reserve(&mut self, size: usize) -> Result<NonNull<c_void>> {
        unsafe { self.heap.reserve(size) }
    }

    pub unsafe fn write_bytes(&mut self, buffer: &[u8]) -> Result<NonNull<c_void>> {
        let write_address = unsafe { self.reserve(buffer.len())? };
        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                write_address.as_ptr() as *mut _,
                buffer.len(),
            );
        }
        Ok(write_address)
    }
}

impl<'a, 'b, C: MemoryController> Drop for MemoryWriteHandle<'a, 'b, C> {
    fn drop(&mut self) {
        unsafe {
            self.heap.make_executable().unwrap();
        }
    }
}
