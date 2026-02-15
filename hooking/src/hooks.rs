use core::ffi;
use core::{ffi::CStr, ptr::NonNull};
use std::ffi::c_void;

use crate::asm::{DefaultHookAssembler, HookAssembler};
use crate::error::{HookingError, Result};
use crate::mem::{DefaultMemoryController, HookHeap, MemoryController};

static HOOK_HEAP: HookHeap<DefaultMemoryController> = HookHeap::new();

#[derive(Debug)]
pub struct Hook<'a, M: MemoryController = DefaultMemoryController> {
    pub data: HookData<'a, M>,
}

impl<'a, M: MemoryController> Hook<'a, M> {
    pub fn apply_hook(&mut self) {}
}

#[derive(Debug)]
pub struct HookData<'a, M: MemoryController> {
    pub symbol_address: NonNull<ffi::c_void>,
    pub trampoline_data: &'a [u8],
    pub restore_stub_data: &'a [u8],
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
        Ok(Hook { data: hook_data })
    }

    pub unsafe fn write_hook_table(
        &self,
        sym_addr: NonNull<ffi::c_void>,
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

        let (restore_stub_address, restore_stub_size) = {
            let restore_stub =
                self.asm
                    .relocate_instructions(eip, sym_addr, trampoline_size, true)?;

            //eip += restore_stub.len();
            (
                unsafe { write_handle.write_bytes(&restore_stub)? },
                restore_stub.len(),
            )
        };

        unsafe {
            let write_restore_addr: usize = restore_stub_address.as_ptr() as usize;
            restore_fn_address.cast().write(write_restore_addr);
        }

        Ok(HookData {
            mem: &self.hook_heap.mem,
            symbol_address: sym_addr,
            trampoline_data: unsafe {
                core::slice::from_raw_parts(
                    trampoline_address.as_ptr() as *const _,
                    trampoline_size,
                )
            },
            restore_stub_data: unsafe {
                core::slice::from_raw_parts(
                    restore_stub_address.as_ptr() as *const _,
                    restore_stub_size,
                )
            },
        })
    }
}
