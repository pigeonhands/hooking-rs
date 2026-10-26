use std::ffi::{CStr, c_void};
use std::mem::MaybeUninit;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::NonNull;

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP, FILE_MAP_EXECUTE, FILE_MAP_READ, FILE_MAP_WRITE, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS,
    MapViewOfFileEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, UnmapViewOfFile, VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::{DualMapping, near_candidates};
use crate::mem::{MemoryError, Protection, Result};

// A multiple of the 64KB allocation granularity.
const NEAR_STEP: usize = 1 << 20;

const PROTECTIONS: [(Protection, u32); 5] = [
    (Protection::NoAccess, PAGE_NOACCESS),
    (Protection::Read, PAGE_READONLY),
    (Protection::ReadWrite, PAGE_READWRITE),
    (Protection::ReadExecute, PAGE_EXECUTE_READ),
    (Protection::ReadWriteExecute, PAGE_EXECUTE_READWRITE),
];

fn to_native(protection: Protection) -> u32 {
    match protection {
        Protection::Native(native) => native as u32,
        protection => PROTECTIONS
            .iter()
            .find(|(p, _)| *p == protection)
            .map(|&(_, native)| native)
            .expect("every protection has a native value"),
    }
}

fn from_native(native: u32) -> Protection {
    PROTECTIONS
        .iter()
        .find(|(_, n)| *n == native)
        .map(|&(protection, _)| protection)
        .unwrap_or(Protection::Native(native as usize))
}

pub fn page_size() -> usize {
    let mut system_info = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe {
        GetSystemInfo(system_info.as_mut_ptr());
        system_info.assume_init().dwPageSize as usize
    }
}

/// Try `map` at addresses moving outwards from `near`, then anywhere.
fn map_near(
    near: Option<usize>,
    mut map: impl FnMut(*const c_void) -> *mut c_void,
) -> Option<NonNull<u8>> {
    // Null lets the system choose an address.
    let mut candidates = near
        .into_iter()
        .flat_map(|near| near_candidates(near, NEAR_STEP))
        .chain([0]);
    candidates.find_map(|candidate| NonNull::new(map(candidate as *const c_void).cast()))
}

unsafe fn map_view(
    mapping: &OwnedHandle,
    access: FILE_MAP,
    len: usize,
    addr: *const c_void,
) -> *mut c_void {
    let mapping = mapping.as_raw_handle();
    unsafe { MapViewOfFileEx(mapping, access, 0, 0, len, addr).Value }
}

pub unsafe fn alloc(
    len: usize,
    protection: Protection,
    near: Option<usize>,
) -> Result<NonNull<u8>> {
    let allocation = MEM_COMMIT | MEM_RESERVE;
    map_near(near, |addr| unsafe {
        VirtualAlloc(addr, len, allocation, to_native(protection))
    })
    .ok_or(MemoryError::CantAllocate)
}

pub unsafe fn free(ptr: NonNull<u8>, _len: usize) {
    unsafe { VirtualFree(ptr.as_ptr().cast(), 0, MEM_RELEASE) };
}

pub unsafe fn protect(ptr: NonNull<u8>, len: usize, protection: Protection) -> Result<()> {
    let mut old_protection = 0u32;
    let success = unsafe {
        VirtualProtect(
            ptr.as_ptr().cast(),
            len,
            to_native(protection),
            &mut old_protection,
        )
    };
    if success == 0 {
        return Err(MemoryError::CantSetMemoryProtection(ptr.as_ptr() as usize));
    }
    Ok(())
}

/// The protection of the page containing `ptr`.
pub fn query_protection(ptr: NonNull<u8>) -> Result<Protection> {
    let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
    if unsafe { VirtualQuery(ptr.as_ptr().cast(), info.as_mut_ptr(), size) } == 0 {
        return Err(MemoryError::CantQueryProtection(ptr.as_ptr() as usize));
    }
    Ok(from_native(unsafe { info.assume_init() }.Protect))
}

pub unsafe fn dual_map(len: usize, near: Option<usize>) -> Result<DualMapping> {
    let (size_high, size_low) = ((len as u64 >> 32) as u32, len as u32);
    let mapping = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_EXECUTE_READWRITE,
            size_high,
            size_low,
            std::ptr::null(),
        )
    };
    if mapping.is_null() {
        return Err(MemoryError::CantMapMemory);
    }
    let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };

    let rw = unsafe { map_view(&mapping, FILE_MAP_WRITE, len, std::ptr::null()) };
    let rw = NonNull::new(rw.cast::<u8>()).ok_or(MemoryError::CantMapMemory)?;

    let rx = map_near(near, |addr| unsafe {
        map_view(&mapping, FILE_MAP_READ | FILE_MAP_EXECUTE, len, addr)
    });
    let Some(rx) = rx else {
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: rw.as_ptr().cast(),
            })
        };
        return Err(MemoryError::CantMapMemory);
    };

    // The views keep the memory alive after `mapping` is closed.
    Ok(DualMapping { rw, rx, len })
}

pub unsafe fn flush_icache(ptr: NonNull<u8>, len: usize) {
    unsafe { FlushInstructionCache(GetCurrentProcess(), ptr.as_ptr().cast(), len) };
}

pub unsafe fn find_symbol(module: Option<&CStr>, symbol: &CStr) -> Result<NonNull<c_void>> {
    let module_handle = match module {
        Some(module) => {
            let handle = unsafe { GetModuleHandleA(module.as_ptr().cast()) };
            if handle.is_null() {
                return Err(MemoryError::CantFindModule(
                    module.to_str().unwrap_or("<invalid-module-name>").into(),
                ));
            }
            handle
        }
        None => std::ptr::null_mut(),
    };

    let address = unsafe { GetProcAddress(module_handle, symbol.as_ptr().cast()) };
    address
        .and_then(|address| NonNull::new(address as *mut c_void))
        .ok_or_else(|| {
            MemoryError::CantFindSymbol(symbol.to_str().unwrap_or("<invalid-symbol-name>").into())
        })
}
