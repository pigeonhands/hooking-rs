use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use super::super::*;
use libc;

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct WindowsMemoryHandle(pub NonNull<c_void>);

impl MemoryHandle for WindowsMemoryHandle {
    fn from_ptr(ptr: NonNull<c_void>) -> Self {
        Self(ptr)
    }
    fn as_ptr(&self) -> NonNull<c_void> {
        self.0
    }
}

pub struct LinuxMemoryAllocationInfo {
    page_size: usize,
    allocation_size: usize,
    allocation_start: WindowsMemoryHandle,
}

impl AllocationInfo<LinuxMemoryController> for LinuxMemoryAllocationInfo {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn allocation_size(&self) -> usize {
        self.allocation_size
    }

    fn allocation_start(&self) -> WindowsMemoryHandle {
        self.allocation_start
    }
}

pub struct LinuxMemoryController;

impl LinuxMemoryController {
    pub const fn new() -> Self {
        Self
    }

    unsafe fn sys_get_page_size(&self) -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    #[cfg(not(feature = "win_close_alloc"))]
    unsafe fn allocate_system_memory(
        &self,
        _page_size: usize,
        size: usize,
    ) -> Result<WindowsMemoryHandle> {
        let handle = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        NonNull::new(handle)
            .map(WindowsMemoryHandle)
            .ok_or(MemoryError::CantAllocate)
    }

    fn allign_up(&self, page_size: usize, address: usize) -> usize {
        (address + page_size - 1) & !(page_size - 1)
    }

    fn allign_down(&self, page_size: usize, address: usize) -> usize {
        address & !(page_size - 1)
    }

    fn get_native_protection_flags(&self, protection: MemoryProtection) -> i32 {
        match protection {
            MemoryProtection::NoAccess => 0,
            MemoryProtection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            MemoryProtection::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
            MemoryProtection::Other(proc) => proc as i32,
        }
    }

    unsafe fn native_set_page_protection(
        &self,
        page: NonNull<c_void>,
        allocation_size: usize,
        protection: i32,
    ) -> Result<()> {
        let success = unsafe { libc::mprotect(page.as_ptr(), allocation_size, protection) == 0 };
        if !success {
            Err(MemoryError::CantSetMemoryProtection(page.as_ptr() as usize))
        } else {
            Ok(())
        }
    }
}

impl MemoryController for LinuxMemoryController {
    type Handle = WindowsMemoryHandle;

    type AllocationInfoType = LinuxMemoryAllocationInfo;

    unsafe fn allocate_memory(&self, min_size: Option<usize>) -> Result<Self::AllocationInfoType> {
        let page_size = unsafe { self.sys_get_page_size() } as usize;

        let allocation_size = if let Some(min_size) = min_size {
            self.allign_up(page_size, min_size)
        } else {
            page_size
        };

        let allocation_start = unsafe { self.allocate_system_memory(page_size, allocation_size)? };

        Ok(Self::AllocationInfoType {
            page_size,
            allocation_size,
            allocation_start,
        })
    }
    unsafe fn set_page_protection(
        &self,
        handle: Self::Handle,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<()> {
        let protection = self.get_native_protection_flags(protection);

        unsafe {
            self.native_set_page_protection(handle.as_ptr(), size, protection)?;
        }

        Ok(())
    }

    unsafe fn get_symbol_address(
        &self,
        module: Option<&CStr>,
        symbol: &CStr,
    ) -> Result<NonNull<c_void>> {
        let module_handle = if let Some(module) = module {
            let module_addr = unsafe { libc::dlopen(module.as_ptr(), libc::RTLD_LAZY) };
            if module_addr.is_null() {
                return Err(MemoryError::CantFindModule(
                    module.to_str().unwrap_or("<invalid-module-name>").into(),
                ));
            }
            module_addr
        } else {
            libc::RTLD_DEFAULT
        };

        let proc_address = {
            let proc_address = unsafe { libc::dlsym(module_handle, symbol.as_ptr()) };

            NonNull::new(proc_address).ok_or_else(|| {
                MemoryError::CantFindModule(
                    symbol.to_str().unwrap_or("<invalid-module-name>").into(),
                )
            })?
        };

        Ok(proc_address)
    }

    fn protection_guard_for_page<'a>(
        &'a self,
        ptr: NonNull<c_void>,
        on_enter: MemoryProtection,
        on_exit: Option<MemoryProtection>,
    ) -> Result<MemoryProtectionGuard<'a, Self>>
    where
        Self: Sized,
    {
        let on_exit = if let Some(on_exit) = on_exit {
            on_exit
        } else {
            MemoryProtection::ReadExecute
        };

        let page_size = unsafe { self.sys_get_page_size() };
        let alligned_address = {
            let address =
                self.allign_down(page_size as usize, ptr.as_ptr() as usize) as *mut c_void;
            NonNull::new(address).ok_or(MemoryError::BadAdress(address))?
        };
        self.protection_guard(
            Self::Handle::from_ptr(alligned_address),
            page_size,
            on_enter,
            on_exit,
        )
    }
}
