use core::cell::UnsafeCell;
use core::ffi;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::mem::ExecWriteGuard;

#[derive(Debug, Default)]
pub(crate) struct HeapState<const HEAP_SIZE: usize> {
    heap_start: Option<NonNull<ffi::c_void>>,
    capacity: usize,
    index: usize,
    page_size: usize,
}

impl<const HEAP_SIZE: usize> HeapState<HEAP_SIZE> {
    pub const fn new() -> Self {
        Self {
            heap_start: None,
            capacity: 0,
            index: 0,
            page_size: 0,
        }
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub unsafe fn heap_addr(&mut self) -> Result<NonNull<ffi::c_void>, ()> {
        if self.heap_start.is_none() {
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
            let mem_size = if HEAP_SIZE == 0 {
                page_size
            } else {
                (HEAP_SIZE + page_size - 1) & !(page_size - 1)
            };
            let mem_addr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    mem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };

            self.heap_start = NonNull::new(mem_addr);
            self.page_size = page_size;
            self.capacity = self.heap_start.map_or(0, |_| mem_size);
        }

        self.heap_start.ok_or(())
    }
}

impl<const HEAP_SIZE: usize> Drop for HeapState<HEAP_SIZE> {
    fn drop(&mut self) {
        let heap_addr = self.heap_start.take();
        if let Some(addr) = heap_addr {
            unsafe {
                libc::munmap(addr.as_ptr(), self.capacity);
            }
        }
    }
}

// TABLE_SIZE = 0 -> use page size
#[derive(Debug)]
pub struct HookHeap<const HEAP_SIZE: usize = 0> {
    locked: AtomicBool,
    pub(crate) state: UnsafeCell<HeapState<HEAP_SIZE>>,
}
unsafe impl<const HEAP_SIZE: usize> Sync for HookHeap<HEAP_SIZE> {}

impl<const HEAP_SIZE: usize> HookHeap<HEAP_SIZE> {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(HeapState::new()),
        }
    }

    fn lock(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }
    fn unlock(&self) {
        self.locked.store(false, Ordering::Relaxed);
    }

    pub fn start_write<'a>(&'a self) -> HookHeapWriter<'a, HEAP_SIZE> {
        HookHeapWriter::lock(&self)
    }
}

pub struct HookHeapWriter<'a, const HEAP_SIZE: usize> {
    heap: &'a HookHeap<HEAP_SIZE>,
}

impl<'a, const HEAP_SIZE: usize> HookHeapWriter<'a, HEAP_SIZE> {
    pub fn lock(heap: &'a HookHeap<HEAP_SIZE>) -> Self {
        heap.lock();
        Self { heap }
    }
    fn state(&self) -> &mut HeapState<HEAP_SIZE> {
        unsafe { &mut *self.heap.state.get() }
    }

    pub fn allocate_heap(&self) {
        let _ = unsafe { self.state().heap_addr() };
    }

    pub fn current_address(&self) -> Result<*const ffi::c_void, ()> {
        unsafe {
            let state = self.state();
            state
                .heap_addr()
                .map(|addr| addr.as_ptr().add(state.index) as *const ffi::c_void)
        }
    }

    pub fn make_heap_writable(&self) -> Result<ExecWriteGuard, ()> {
        let state = self.state();
        let write_address = unsafe { state.heap_addr()?.add(state.index) };
        let write_handle = ExecWriteGuard::write_to(write_address, state.page_size);
        Ok(write_handle)
    }

    pub fn write_bytes(&mut self, buffer: &[u8]) -> Result<NonNull<ffi::c_void>, ()> {
        let state = self.state();
        if state.index + buffer.len() > state.capacity {
            return Err(());
        }

        let write_address = unsafe { state.heap_addr()?.add(state.index) };

        unsafe {
            ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                write_address.as_ptr() as *mut _,
                buffer.len(),
            );
        }

        state.index += buffer.len();

        Ok(write_address)
    }
}
impl<'a, const HEAP_SIZE: usize> Drop for HookHeapWriter<'a, HEAP_SIZE> {
    fn drop(&mut self) {
        self.heap.unlock();
    }
}
