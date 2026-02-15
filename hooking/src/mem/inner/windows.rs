use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

use super::super::*;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_READWRITE,
    VirtualAlloc, VirtualProtect, VirtualQuery,
};

use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

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
        unsafe {
            let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetSystemInfo(system_info.as_mut_ptr());
            system_info.assume_init()
        }
    }

    #[cfg(feature = "win_close_alloc")]
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
            self.allign_up(page_size, dummy as *const c_void as usize) + page_size
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

        NonNull::new(handle)
            .map(WindowsMemoryHandle)
            .ok_or(MemoryError::CantAllocate)
    }

    #[cfg(not(feature = "win_close_alloc"))]
    unsafe fn allocate_system_memory(
        &self,
        _page_size: usize,
        size: usize,
    ) -> Result<WindowsMemoryHandle> {
        let handle = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
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

    fn get_native_protection_flags(&self, protection: MemoryProtection) -> u32 {
        match protection {
            MemoryProtection::NoAccess => 0,
            MemoryProtection::ReadWrite => PAGE_READWRITE,
            MemoryProtection::ReadExecute => PAGE_EXECUTE_READ,
            MemoryProtection::Other(proc) => proc as u32,
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

    unsafe fn get_page_info(&self, ptr: *const c_void) -> Result<MEMORY_BASIC_INFORMATION> {
        let memory_info = unsafe {
            let mut memory_info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            let res = VirtualQuery(
                ptr,
                memory_info.as_mut_ptr(),
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if res == 0 {
                None
            } else {
                Some(memory_info.assume_init())
            }
        };

        memory_info.ok_or(MemoryError::BadAdress(ptr))
    }
}

impl MemoryController for WindowsMemoryController {
    type Handle = WindowsMemoryHandle;

    type AllocationInfoType = WindowsMemoryAllocationInfo;

    unsafe fn allocate_memory(&self, min_size: Option<usize>) -> Result<Self::AllocationInfoType> {
        let page_size = unsafe { self.get_system_info().dwPageSize } as usize;

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
                .and_then(NonNull::new)
                .ok_or_else(|| {
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
            let memory_info = unsafe { self.get_page_info(ptr.as_ptr())? };
            MemoryProtection::Other(memory_info.Protect as usize)
        };

        let page_size = unsafe { self.get_system_info() }.dwPageSize as usize;
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
