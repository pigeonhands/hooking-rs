use std::ffi::{CStr, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

use super::{DualMapping, in_rel32_range, near_candidates};
use crate::mem::{MemoryError, Protection, Result};

const NEAR_STEP: usize = 1 << 20;

const PROTECTIONS: [(Protection, i32); 5] = [
    (Protection::NoAccess, libc::PROT_NONE),
    (Protection::Read, libc::PROT_READ),
    (Protection::ReadWrite, libc::PROT_READ | libc::PROT_WRITE),
    (Protection::ReadExecute, libc::PROT_READ | libc::PROT_EXEC),
    (
        Protection::ReadWriteExecute,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    ),
];

fn to_native(protection: Protection) -> i32 {
    match protection {
        Protection::Native(native) => native as i32,
        protection => PROTECTIONS
            .iter()
            .find(|(p, _)| *p == protection)
            .map(|&(_, native)| native)
            .expect("every protection has a native value"),
    }
}

fn from_native(native: i32) -> Protection {
    PROTECTIONS
        .iter()
        .find(|(_, n)| *n == native)
        .map(|&(protection, _)| protection)
        .unwrap_or(Protection::Native(native as usize))
}

/// Parse the `rwxp` permissions column of `/proc/self/maps`.
fn from_perms(perms: &str) -> Protection {
    let has = |index: usize, flag: u8| perms.as_bytes().get(index) == Some(&flag);
    let mut native = libc::PROT_NONE;
    if has(0, b'r') {
        native |= libc::PROT_READ;
    }
    if has(1, b'w') {
        native |= libc::PROT_WRITE;
    }
    if has(2, b'x') {
        native |= libc::PROT_EXEC;
    }
    from_native(native)
}

pub fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

unsafe fn mmap(
    addr: *mut c_void,
    len: usize,
    protection: Protection,
    flags: i32,
    fd: Option<&OwnedFd>,
) -> Option<NonNull<u8>> {
    let fd = fd.map_or(-1, |fd| fd.as_raw_fd());
    let ptr = unsafe { libc::mmap(addr, len, to_native(protection), flags, fd, 0) };
    if ptr == libc::MAP_FAILED {
        None
    } else {
        NonNull::new(ptr.cast())
    }
}

/// Map `len` bytes as close to `near` as possible, falling back to anywhere.
/// `map` is given an address hint and extra mmap flags.
fn map_near(
    near: Option<usize>,
    len: usize,
    mut map: impl FnMut(*mut c_void, i32) -> Option<NonNull<u8>>,
) -> Option<NonNull<u8>> {
    if let Some(near) = near {
        for candidate in near_candidates(near, NEAR_STEP) {
            let Some(addr) = map(candidate as *mut c_void, libc::MAP_FIXED_NOREPLACE) else {
                continue;
            };
            // Kernels before 4.17 treat MAP_FIXED_NOREPLACE as just a hint.
            if in_rel32_range(near, addr.as_ptr() as usize) {
                return Some(addr);
            }
            unsafe { free(addr, len) };
        }
    }
    map(std::ptr::null_mut(), 0)
}

fn create_memfd(len: usize) -> Result<OwnedFd> {
    let fd = unsafe { libc::memfd_create(c"hooking".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(MemoryError::CantMapMemory);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
        return Err(MemoryError::CantMapMemory);
    }
    Ok(fd)
}

/// Map a writable view of `fd`.
unsafe fn map_writable(fd: &OwnedFd, len: usize) -> Result<NonNull<u8>> {
    let null = std::ptr::null_mut();
    unsafe { mmap(null, len, Protection::ReadWrite, libc::MAP_SHARED, Some(fd)) }
        .ok_or(MemoryError::CantMapMemory)
}

pub unsafe fn alloc(
    len: usize,
    protection: Protection,
    near: Option<usize>,
) -> Result<NonNull<u8>> {
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    map_near(near, len, |hint, extra_flags| unsafe {
        mmap(hint, len, protection, flags | extra_flags, None)
    })
    .ok_or(MemoryError::CantAllocate)
}

pub unsafe fn free(ptr: NonNull<u8>, len: usize) {
    unsafe { libc::munmap(ptr.as_ptr().cast(), len) };
}

pub unsafe fn protect(ptr: NonNull<u8>, len: usize, protection: Protection) -> Result<()> {
    if unsafe { libc::mprotect(ptr.as_ptr().cast(), len, to_native(protection)) } != 0 {
        return Err(MemoryError::CantSetMemoryProtection(ptr.as_ptr() as usize));
    }
    Ok(())
}

/// The protection of the page containing `ptr`.
pub fn query_protection(ptr: NonNull<u8>) -> Result<Protection> {
    let addr = ptr.as_ptr() as usize;
    let error = || MemoryError::CantQueryProtection(addr);
    let maps = std::fs::read("/proc/self/maps").map_err(|_| error())?;

    String::from_utf8_lossy(&maps)
        .lines()
        .find_map(|line| {
            // Each line starts with `start-end perms`, in hex.
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let start = usize::from_str_radix(start, 16).ok()?;
            let end = usize::from_str_radix(end, 16).ok()?;
            let perms = fields.next()?;
            (start..end).contains(&addr).then(|| from_perms(perms))
        })
        .ok_or_else(error)
}

pub unsafe fn dual_map(len: usize, near: Option<usize>) -> Result<DualMapping> {
    let fd = create_memfd(len)?;
    let rw = unsafe { map_writable(&fd, len)? };

    let rx = map_near(near, len, |hint, extra_flags| unsafe {
        let flags = libc::MAP_SHARED | extra_flags;
        mmap(hint, len, Protection::ReadExecute, flags, Some(&fd))
    });
    let Some(rx) = rx else {
        unsafe { free(rw, len) };
        return Err(MemoryError::CantMapMemory);
    };

    // The mappings keep the memory alive after `fd` is closed.
    Ok(DualMapping { rw, rx, len })
}

/// Replace the pages at `[page, page + len)` with a memfd-backed copy that
/// has the same bytes and protection, and return a writable view of it.
///
/// The replacement is a single `mmap(MAP_FIXED)`, so the pages are never
/// missing or non-executable for threads running code on them.
pub unsafe fn alias_pages(page: NonNull<u8>, len: usize) -> Result<NonNull<u8>> {
    let protection = query_protection(page)?;
    let fd = create_memfd(len)?;
    let rw = unsafe { map_writable(&fd, len)? };
    unsafe { std::ptr::copy_nonoverlapping(page.as_ptr(), rw.as_ptr(), len) };

    let flags = libc::MAP_SHARED | libc::MAP_FIXED;
    let replaced = unsafe { mmap(page.as_ptr().cast(), len, protection, flags, Some(&fd)) };
    if replaced != Some(page) {
        unsafe { free(rw, len) };
        return Err(MemoryError::CantMapMemory);
    }

    Ok(rw)
}

pub unsafe fn flush_icache(_ptr: NonNull<u8>, _len: usize) {
    // x86 keeps the instruction cache coherent with stores.
}

pub unsafe fn find_symbol(module: Option<&CStr>, symbol: &CStr) -> Result<NonNull<c_void>> {
    let module_handle = match module {
        Some(module) => {
            let handle = unsafe { libc::dlopen(module.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                return Err(MemoryError::CantFindModule(
                    module.to_str().unwrap_or("<invalid-module-name>").into(),
                ));
            }
            handle
        }
        None => libc::RTLD_DEFAULT,
    };

    let address = unsafe { libc::dlsym(module_handle, symbol.as_ptr()) };
    NonNull::new(address).ok_or_else(|| {
        MemoryError::CantFindSymbol(symbol.to_str().unwrap_or("<invalid-symbol-name>").into())
    })
}
