use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use std::ffi::c_void;

use crate::asm::{DefaultHookAssembler, HookAssembler};
use crate::error::{HookingError, Result};
use crate::mem::{DefaultMemoryController, HookHeap, MemoryController, MemoryProtection};

static HOOK_HEAP: HookHeap<DefaultMemoryController> = HookHeap::new();

#[derive(Debug)]
pub struct Hook<'a, M: MemoryController = DefaultMemoryController> {
    pub data: HookData<'a, M>,
    is_applied: bool,
}

impl Hook<'static, DefaultMemoryController> {
    pub unsafe fn by_name(
        module: Option<&CStr>,
        symbol: &CStr,
        destination: *mut u8,
    ) -> Result<Self> {
        let hook_writer = HookWriter::from_static();
        unsafe { hook_writer.create_hook_by_name(module, symbol, destination) }
    }

    pub unsafe fn create(target: *mut u8, destination: *mut u8) -> Result<Self> {
        let hook_writer = HookWriter::from_static();
        unsafe {
            hook_writer.create_hook(
                NonNull::new(target as *mut _)
                    .ok_or(HookingError::InvalidTarget(target as *const _))?,
                NonNull::new(destination as *mut _)
                    .ok_or(HookingError::InvalidDestination(destination as *const _))?,
            )
        }
    }
}

impl<'a, M: MemoryController> Hook<'a, M> {
    pub unsafe fn apply_hook(&mut self) -> Result<()> {
        if self.is_applied {
            return Ok(());
        }
        let HookData {
            mem,
            patch_data,
            symbol_address,
            ..
        } = &self.data;

        let _protection_guard =
            mem.protection_guard_for_page(*symbol_address, MemoryProtection::ReadWrite, None)?;

        unsafe {
            std::ptr::copy_nonoverlapping(
                patch_data.as_ptr(),
                symbol_address.as_ptr() as *mut _,
                patch_data.len(),
            );
        }
        self.is_applied = true;

        Ok(())
    }
    pub unsafe fn remove_hook(&mut self) -> Result<()> {
        if !self.is_applied {
            return Ok(());
        }

        let HookData {
            mem,
            patch_data,
            original_instructions,
            symbol_address,
            ..
        } = &self.data;

        let _protection_guard =
            mem.protection_guard_for_page(*symbol_address, MemoryProtection::ReadWrite, None)?;

        unsafe {
            std::ptr::copy_nonoverlapping(
                original_instructions.as_ptr(),
                symbol_address.as_ptr() as *mut _,
                patch_data.len(),
            );
        }

        self.is_applied = false;

        Ok(())
    }
}

#[derive(Debug)]
pub struct HookData<'a, M: MemoryController> {
    pub symbol_address: NonNull<ffi::c_void>,
    pub trampoline_data: &'a [u8],
    pub original_fn_call_stub_data: &'a [u8],
    pub patch_data: Vec<u8>,
    pub original_instructions: Vec<u8>,
    mem: &'a M,
}

pub struct HookWriter<'a, M: MemoryController, A: HookAssembler> {
    hook_heap: &'a HookHeap<M>,
    asm: A,
}

impl HookWriter<'static, DefaultMemoryController, DefaultHookAssembler> {
    pub const fn from_static() -> Self {
        Self::new(&HOOK_HEAP, DefaultHookAssembler::new())
    }
}

impl<'a, M: MemoryController, A: HookAssembler> HookWriter<'a, M, A> {
    pub const fn new(hook_heap: &'a HookHeap<M>, assembler: A) -> Self {
        Self {
            hook_heap,
            asm: assembler,
        }
    }

    pub unsafe fn create_hook_by_name(
        &self,
        module: Option<&CStr>,
        symbol: &CStr,
        destination: *mut u8,
    ) -> Result<Hook<'a, M>> {
        let destination = NonNull::new(destination as *mut c_void).ok_or_else(|| {
            HookingError::NoDestination(symbol.to_str().unwrap_or("<invalid-symbol-name>").into())
        })?;

        unsafe {
            let symbol_address = self.hook_heap.mem.get_symbol_address(module, symbol)?;
            self.create_hook(symbol_address, destination)
        }
    }

    pub unsafe fn create_hook(
        &self,
        target: NonNull<c_void>,
        destination: NonNull<c_void>,
    ) -> Result<Hook<'a, M>> {
        let hook_data = unsafe { self.write_hook_table(target, destination)? };
        Ok(Hook {
            data: hook_data,
            is_applied: false,
        })
    }

    pub unsafe fn write_hook_table(
        &self,
        target: NonNull<ffi::c_void>,
        destination_fn: NonNull<ffi::c_void>,
    ) -> Result<HookData<'a, M>> {
        let mut heap_handle = self.hook_heap.get_handle()?;
        let mut write_handle = heap_handle.begin_write()?;

        let restore_fn_address = unsafe { write_handle.reserve(std::mem::size_of::<usize>())? };
        let mut eip = unsafe { write_handle.write_address()? }.as_ptr() as usize;

        let (trampoline_address, trampoline_size) = {
            let trampoline =
                self.asm
                    .assemble_trampoline(eip, destination_fn, Some(restore_fn_address))?;

            eip += trampoline.len();

            (
                unsafe { write_handle.write_bytes(&trampoline)? },
                trampoline.len(),
            )
        };

        let patch = self
            .asm
            .assemble_patch(target.as_ptr() as usize, trampoline_address)?;

        let (original_fn_call_stub_address, restore_stub_size) = {
            let restore_stub = self
                .asm
                .relocate_instructions(eip, target, patch.len(), true)?;

            //eip += restore_stub.len();
            (
                unsafe { write_handle.write_bytes(&restore_stub)? },
                restore_stub.len(),
            )
        };

        unsafe {
            let write_restore_addr: usize = original_fn_call_stub_address.as_ptr() as usize;
            restore_fn_address.cast().write(write_restore_addr);
        }

        let original_fn_instructions =
            unsafe { std::slice::from_raw_parts(target.as_ptr() as *const u8, patch.len()) };

        Ok(HookData {
            mem: &self.hook_heap.mem,
            symbol_address: target,
            patch_data: patch,
            original_instructions: original_fn_instructions.into(),
            trampoline_data: unsafe {
                core::slice::from_raw_parts(
                    trampoline_address.as_ptr() as *const _,
                    trampoline_size,
                )
            },
            original_fn_call_stub_data: unsafe {
                core::slice::from_raw_parts(
                    original_fn_call_stub_address.as_ptr() as *const _,
                    restore_stub_size,
                )
            },
        })
    }
}
