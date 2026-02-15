use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use super::super::*;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAlloc, VirtualProtect,
};

use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct WindowsMemoryHandle(pub NonNull<c_void>);

impl MemoryHandle for WindowsMemoryHandle {
    fn as_ptr(&self) -> NonNull<c_void> {
        self.0
    }
}

impl WindowsMemoryHandle {
    pub fn from_ptr(ptr: *mut c_void) -> Option<Self> {
        NonNull::new(ptr).map(Self)
    }
}

pub struct WindowsMemoryAllocationInfo {
    page_size: usize,
    allocation_size: usize,
    allocation_start: WindowsMemoryHandle,
}

impl AllocationInfo<WindowsMemoryController> for WindowsMemoryAllocationInfo {
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

pub struct WindowsMemoryController;

impl WindowsMemoryController {
    pub const fn new() -> Self {
        Self
    }

    unsafe fn get_system_info(&self) -> SYSTEM_INFO {
        let system_info = unsafe {
            let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init()
        };
        system_info
    }

    unsafe fn allocate_system_memory(
        &self,
        page_size: usize,
        size: usize,
    ) -> Result<WindowsMemoryHandle> {
        // Windows 64bit will allcoate memory very far away
        // from where modules are loaded by default.
        // So try and load some memory that is a bit closer
        let mut allocation_address = {
            fn dummy() {}
            self.allign(page_size, dummy as *const c_void as usize) + page_size
        };

        let handle = 'memaddr: {
            for _ in 0..0x1000 {
                let addr = unsafe {
                    VirtualAlloc(
                        allocation_address as *mut _,
                        size,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE,
                    )
                };
                if !addr.is_null() {
                    break 'memaddr addr;
                }
                allocation_address += page_size;
            }
            std::ptr::null_mut()
        };

        WindowsMemoryHandle::from_ptr(handle).ok_or(MemoryError::CantAllocate)
    }

    fn allign(&self, page_size: usize, address: usize) -> usize {
        (address as usize + page_size - 1) & !(page_size - 1)
    }
    fn get_native_protection_flags(&self, protection: MemoryProtection) -> u32 {
        match protection {
            MemoryProtection::NoAccess => 0,
            MemoryProtection::ReadWrite => PAGE_READWRITE,
            MemoryProtection::ReadExecute => PAGE_EXECUTE_READ,
        }
    }

    unsafe fn native_set_page_protection(
        &self,
        page: NonNull<c_void>,
        allocation_size: usize,
        protection: u32,
    ) -> Result<()> {
        let success = unsafe {
            let mut old_protection = 0u32;
            VirtualProtect(
                page.as_ptr(),
                allocation_size,
                protection,
                &mut old_protection,
            ) != 0
        };
        if !success {
            Err(MemoryError::CantSetMemoryProtection(page.as_ptr() as usize))
        } else {
            Ok(())
        }
    }
}

impl MemoryController for WindowsMemoryController {
    type Handle = WindowsMemoryHandle;

    type AllocationInfoType = WindowsMemoryAllocationInfo;

    unsafe fn allocate_memory(&self, min_size: Option<usize>) -> Result<Self::AllocationInfoType> {
        let page_size = unsafe { self.get_system_info().dwPageSize } as usize;

        let allocation_size = if let Some(min_size) = min_size {
            self.allign(page_size, min_size)
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
            let module_addr = unsafe { GetModuleHandleA(module.as_ptr() as *const _) };
            if module_addr.is_null() {
                return Err(MemoryError::CantFindModule(
                    module.to_str().unwrap_or("<invalid-module-name>").into(),
                ));
            }
            module_addr
        } else {
            std::ptr::null_mut()
        };

        let proc_address = {
            let proc_address =
                unsafe { GetProcAddress(module_handle, symbol.as_ptr() as *const _) };

            proc_address
                .map(|proc| proc as *mut c_void)
                .map(NonNull::new)
                .flatten()
                .ok_or_else(|| {
                    MemoryError::CantFindModule(
                        symbol.to_str().unwrap_or("<invalid-module-name>").into(),
                    )
                })?
        };

        Ok(proc_address)
    }
}
