use core::ffi;
use core::ptr::NonNull;

pub struct ExecWriteGuard {
    page: NonNull<ffi::c_void>,
    page_size: usize,
    write_address: NonNull<ffi::c_void>,
}

impl ExecWriteGuard {
    pub fn write_to(write_address: NonNull<ffi::c_void>, page_size: usize) -> Self {
        let page =
            NonNull::new((write_address.as_ptr() as usize & !(page_size - 1)) as *mut libc::c_void)
                .unwrap();
        let mut guard = Self {
            page,
            page_size,
            write_address,
        };
        unsafe {
            guard.set_protection(libc::PROT_READ | libc::PROT_WRITE);
        }
        guard
    }

    pub fn as_ptr(&mut self) -> *mut u8 {
        self.write_address.as_ptr() as *mut u8
    }

    pub unsafe fn set_protection(&mut self, prot: ffi::c_int) -> bool {
        unsafe { libc::mprotect(self.page.as_ptr(), self.page_size, prot) != 0 }
    }
}

impl Drop for ExecWriteGuard {
    fn drop(&mut self) {
        unsafe {
            self.set_protection(libc::PROT_READ | libc::PROT_EXEC);
        }
    }
}
